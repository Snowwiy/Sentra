"""Validación de la salida del modelo: schema y grounding (Fase 4J).

La respuesta del modelo es texto no confiable. Antes de guardarla o mostrarla:
1. se interpreta como JSON (sin evaluar nada; solo json.loads) y se valida con un schema
   estricto con límites de longitud;
2. cada referencia de evidencia se comprueba contra el mapa del context builder: solo valen
   los identificadores que Sentra puso en el contexto. Las demás se descartan (el modelo no
   puede inventar IDs) y se cuentan;
3. un hallazgo sin evidencia válida se descarta. Si el modelo daba hallazgos y ninguno
   sobrevive, la respuesta entera se rechaza: no se presenta como análisis válido;
4. se señalan (warnings) afirmaciones de compromiso confirmado que la evidencia no respalda.

El resultado final lleva referencias resueltas (tipo, id público, etiqueta) y el texto con
los seudónimos ya restaurados; la UI lo pinta siempre como texto plano.
"""

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.ai.context import AIContext
from app.ai.provider import AIInvalidResponseError, AIResponse, AIUngroundedResponseError
from app.detection.text import clean

Certainty = Literal["observed", "detected", "correlated", "possible", "requires_validation"]

_REF = re.compile(r"^[A-Z]\d{1,4}$")
# Afirmaciones de compromiso confirmado (es/en). Solo se aceptan sin aviso si hay una
# detección de confianza alta y severidad alta o crítica en el contexto.
_STRONG_CLAIM = re.compile(
    r"\b(fue|ha sido|está|esta|est[aá]n|han sido)\s+(comprometid|hackead|infectad)\w*"
    r"|\b(is|was|has been|have been)\s+(compromised|hacked|breached|infected)\b"
    r"|\bcompromiso confirmado\b|\bconfirmed (compromise|breach)\b",
    re.IGNORECASE,
)


class _Model(BaseModel):
    # Campos extra se ignoran (los modelos añaden claves); los conocidos se validan.
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)


class RawFinding(_Model):
    text: str = Field(min_length=1, max_length=600)
    certainty: Certainty = "requires_validation"
    evidence: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("certainty", mode="before")
    @classmethod
    def _certainty(cls, value: object) -> object:
        # Un valor fuera del vocabulario se degrada a "requires_validation" (nunca sube).
        allowed = {"observed", "detected", "correlated", "possible", "requires_validation"}
        if isinstance(value, str) and value.strip().lower() in allowed:
            return value.strip().lower()
        return "requires_validation"


class RawAction(_Model):
    text: str = Field(min_length=1, max_length=500)
    evidence: list[str] = Field(default_factory=list, max_length=12)


class RawInsight(_Model):
    summary: str = Field(min_length=1, max_length=1500)
    assessment: str = Field(default="", max_length=2500)
    confidence_note: str = Field(default="", max_length=600)
    key_findings: list[RawFinding] = Field(default_factory=list, max_length=12)
    recommended_actions: list[RawAction] = Field(default_factory=list, max_length=10)
    evidence_refs: list[str] = Field(default_factory=list, max_length=60)
    limitations: list[str] = Field(default_factory=list, max_length=8)
    insufficient_data: bool = False

    @field_validator("key_findings", "recommended_actions", "evidence_refs", mode="before")
    @classmethod
    def _null_list(cls, value: object) -> object:
        return [] if value is None else value


# Fase 7C.1: bloques de razonamiento que emiten modelos open-weight "thinking" (Qwen3,
# DeepSeek-R1, QwQ, algunos GGUF de llama.cpp) antes de la respuesta. No son la respuesta ni
# se guardan: se quitan antes de interpretar el JSON. Un bloque sin cerrar (el modelo agotó
# max_tokens pensando) deja la respuesta vacía y acaba en ai_invalid_response con el motivo
# truncated_reasoning (7C-Fix2, answer_content).
_REASONING = re.compile(
    r"<(think|thinking|reasoning|reflection)>.*?(</\1>|\Z)", re.DOTALL | re.IGNORECASE
)
_FENCE = re.compile(r"```(?:json|JSON)?\s*(\{.*?\})\s*```", re.DOTALL)
# Límite de búsqueda del objeto JSON dentro de un texto con prosa alrededor: una respuesta
# legítima cabe de sobra; un texto enorme no se recorre carácter a carácter.
_MAX_SCAN = 256 * 1024


def _balanced_object(text: str) -> str | None:
    """Primer objeto JSON equilibrado y válido de `text` (respeta cadenas y escapes), o None.

    Solo localiza llaves y comprueba el candidato con json.loads (nunca se evalúa nada). Un
    candidato que no es JSON ("{previa}" en la prosa) se salta y se prueba el siguiente.
    """
    limit = min(len(text), _MAX_SCAN)
    start = text.find("{")
    while 0 <= start < limit:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, limit):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : index + 1]
                    try:
                        if isinstance(json.loads(candidate), dict):
                            return candidate
                    except ValueError:
                        pass
                    break
        start = text.find("{", start + 1)
    return None


def extract_json_text(content: str) -> str:
    """Texto JSON de una respuesta de modelo, tolerante con modelos open-weight.

    Orden: quitar razonamiento <think>…</think>; respuesta entera si ya es JSON; bloque
    ```json``` en cualquier posición; primer objeto equilibrado dentro de prosa ("Aquí
    tienes el análisis: {...}"). Si nada encaja se devuelve el texto tal cual y json.loads
    falla con un error controlado.
    """
    text = _REASONING.sub("", content).strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    fenced = _FENCE.search(text)
    if fenced:
        return fenced.group(1)
    found = _balanced_object(text)
    return found if found is not None else text


def answer_content(response: AIResponse) -> str:
    """Contenido utilizable de la respuesta, o AIInvalidResponseError con el motivo (7C-Fix2).

    Distingue lo que antes era un único "respuesta no válida": el servidor cortó por
    max_tokens (`finish_reason="length"`) mientras el modelo razonaba (`truncated_reasoning`)
    o sin razonamiento visible (`truncated`); terminó solo con razonamiento
    (`reasoning_only`); o no devolvió nada (`empty_answer`). Solo mira tamaños y marcas, nunca
    guarda ni registra el texto.
    """
    text = _REASONING.sub("", response.content).strip()
    if text:
        return response.content
    thought = response.reasoning_chars > 0 or _REASONING.search(response.content) is not None
    if response.finish_reason == "length":
        raise AIInvalidResponseError(
            "The AI model used its whole output budget before answering",
            "truncated_reasoning" if thought else "truncated",
        )
    raise AIInvalidResponseError(
        "The AI model returned no answer", "reasoning_only" if thought else "empty_answer"
    )


def _load_object(content: str, truncated: bool) -> dict[str, Any]:
    # Con finish_reason="length" un JSON roto es una respuesta cortada, no un modelo que no
    # sabe escribir JSON: reintentar con el mismo presupuesto daría lo mismo.
    reason = "truncated" if truncated else "invalid_json"
    try:
        data = json.loads(extract_json_text(content))
    except ValueError:
        raise AIInvalidResponseError("The AI response is not valid JSON", reason) from None
    if not isinstance(data, dict):
        raise AIInvalidResponseError("The AI response is not a JSON object", reason)
    return data


def parse_json(content: str, truncated: bool = False) -> RawInsight:
    """JSON del modelo -> RawInsight, o AIInvalidResponseError (nunca se evalúa nada).

    Un JSON genérico ({"status": "ok"}) no es un análisis: sin `summary` no cumple el schema.
    """
    data = _load_object(content, truncated)
    try:
        return RawInsight.model_validate(data)
    except ValidationError:
        raise AIInvalidResponseError(
            "The AI response does not match the expected format", "schema_mismatch"
        ) from None


def _resolve(refs: list[str], ctx: AIContext, dropped: list[str]) -> list[str]:
    valid: list[str] = []
    for raw in refs:
        ref = str(raw).strip().upper()
        if _REF.match(ref) and ref in ctx.refs:
            if ref not in valid:
                valid.append(ref)
        else:
            dropped.append(clean(raw, 32))
    return valid


def _has_strong_evidence(ctx: AIContext) -> bool:
    for section in (
        "active_detections",
        "detection",
        "detections_in_window",
        "incident_detections",
    ):
        value = ctx.data.get(section)
        items: list[Any]
        if isinstance(value, dict) and "items" in value:
            items = value["items"]
        elif isinstance(value, dict):
            items = [value]
        else:
            items = value or []
        for d in items:
            if (
                isinstance(d, dict)
                and d.get("confidence") == "high"
                and d.get("severity") in ("high", "critical")
            ):
                return True
    return False


def ground(raw: RawInsight, ctx: AIContext) -> dict[str, Any]:
    """Valida referencias y devuelve el resultado listo para guardar y mostrar."""
    dropped: list[str] = []
    restore = ctx.redactor.restore

    findings: list[dict[str, Any]] = []
    discarded_findings = 0
    for f in raw.key_findings:
        valid = _resolve(f.evidence, ctx, dropped)
        if not valid:
            # Sin evidencia válida (no citó nada, o solo IDs inventados): no es un hallazgo
            # grounded y no se muestra.
            discarded_findings += 1
            continue
        findings.append(
            {"text": restore(clean(f.text, 600)), "certainty": f.certainty, "evidence": valid}
        )
    if raw.key_findings and not findings:
        raise AIUngroundedResponseError(
            "The AI answer cited no valid Sentra evidence; it is not shown as an analysis"
        )

    actions = []
    for a in raw.recommended_actions:
        actions.append(
            {
                "text": restore(clean(a.text, 500)),
                "evidence": _resolve(a.evidence, ctx, dropped),
            }
        )

    cited = _resolve(raw.evidence_refs, ctx, dropped)
    for item in [*findings, *actions]:
        cited.extend(r for r in item["evidence"] if r not in cited)

    limitations = [restore(clean(item, 300)) for item in raw.limitations if str(item).strip()]
    warnings: list[str] = []
    if dropped:
        warnings.append(
            f"Se descartaron {len(dropped)} referencias de evidencia que no existen en Sentra."
        )
    if discarded_findings:
        warnings.append(
            f"Se descartaron {discarded_findings} hallazgos sin evidencia válida de Sentra."
        )
    summary = restore(clean(raw.summary, 1500))
    assessment = restore(clean(raw.assessment, 2500))
    if _STRONG_CLAIM.search(f"{summary} {assessment}") and not _has_strong_evidence(ctx):
        warnings.append(
            "El texto afirma un compromiso que Sentra no respalda con detecciones de confianza "
            "alta: trátelo como hipótesis y valide la evidencia."
        )
    insufficient = raw.insufficient_data or (not findings and not cited)

    return {
        "summary": summary,
        "assessment": assessment,
        "confidence_note": restore(clean(raw.confidence_note, 600)),
        "key_findings": findings,
        "recommended_actions": actions,
        "evidence_refs": [{"ref": r, **ctx.refs[r].as_dict()} for r in cited],
        "limitations": limitations,
        "insufficient_data": insufficient,
        "warnings": warnings,
        "dropped_refs": len(dropped),
    }


def insufficient_result(reason: str) -> dict[str, Any]:
    """Resultado determinista cuando no hay datos: no se llama al modelo ni se inventa nada."""
    return {
        "summary": "No hay datos suficientes en Sentra para responder.",
        "assessment": reason,
        "confidence_note": "Sin evidencia disponible.",
        "key_findings": [],
        "recommended_actions": [],
        "evidence_refs": [],
        "limitations": [reason],
        "insufficient_data": True,
        "warnings": [],
        "dropped_refs": 0,
    }


# --- Fase 7C.2: asistencia contextual de la Analyst Console -------------------------------


class RawHypothesis(_Model):
    text: str = Field(min_length=1, max_length=500)
    evidence: list[str] = Field(default_factory=list, max_length=12)
    # Qué tendría que comprobar el analista para confirmarla o descartarla.
    validate_with: str = Field(default="", max_length=300)


class RawConsoleInsight(RawInsight):
    hypotheses: list[RawHypothesis] = Field(default_factory=list, max_length=8)
    # Borrador de nota analítica (solo la tarea draft_note); texto plano.
    draft: str = Field(default="", max_length=4000)

    @field_validator("hypotheses", mode="before")
    @classmethod
    def _null_hypotheses(cls, value: object) -> object:
        return [] if value is None else value

    @field_validator("draft", mode="before")
    @classmethod
    def _null_draft(cls, value: object) -> object:
        return "" if value is None else value


def parse_console_json(content: str, truncated: bool = False) -> RawConsoleInsight:
    data = _load_object(content, truncated)
    try:
        return RawConsoleInsight.model_validate(data)
    except ValidationError:
        raise AIInvalidResponseError(
            "The AI response does not match the expected format", "schema_mismatch"
        ) from None


# Encabezado fijo del borrador: aunque el analista lo copie a un caso, el texto sigue diciendo
# de dónde salió. Lo pone Sentra, no el modelo (el modelo no puede quitarlo).
DRAFT_HEADER = "[Borrador generado por IA local: revisar contra la evidencia antes de usarlo]"


def _clean_multiline(value: str, limit: int, max_lines: int = 60) -> str:
    """Como clean() pero conserva los saltos de línea (párrafos del borrador)."""
    lines = [clean(line, limit) for line in value.replace("\r\n", "\n").split("\n")]
    # Varias líneas vacías seguidas se quedan en una (el modelo a veces rellena).
    compact: list[str] = []
    for line in lines[: max_lines * 2]:
        if line or (compact and compact[-1]):
            compact.append(line)
    return "\n".join(compact[:max_lines]).strip()[:limit]


def ground_console(raw: RawConsoleInsight, ctx: AIContext) -> dict[str, Any]:
    """Grounding de la consola: el de 4J más hipótesis y borrador.

    Una hipótesis es siempre una sugerencia del modelo: su certeza se fija en "possible"
    (no la elige el modelo) y sin evidencia válida se descarta como un hallazgo.
    """
    result = ground(raw, ctx)
    dropped: list[str] = []
    restore = ctx.redactor.restore
    hypotheses: list[dict[str, Any]] = []
    discarded = 0
    for h in raw.hypotheses:
        valid = _resolve(h.evidence, ctx, dropped)
        if not valid:
            discarded += 1
            continue
        hypotheses.append(
            {
                "text": restore(clean(h.text, 500)),
                "certainty": "possible",
                "evidence": valid,
                "validate_with": restore(clean(h.validate_with, 300)),
            }
        )
    cited = [item["ref"] for item in result["evidence_refs"]]
    for h_item in hypotheses:
        for ref in h_item["evidence"]:
            if ref not in cited:
                cited.append(ref)
                result["evidence_refs"].append({"ref": ref, **ctx.refs[ref].as_dict()})
    if dropped:
        result["dropped_refs"] += len(dropped)
        result["warnings"].append(
            f"Se descartaron {len(dropped)} referencias de hipótesis que no existen en Sentra."
        )
    if discarded:
        result["warnings"].append(f"Se descartaron {discarded} hipótesis sin evidencia de Sentra.")
    draft = restore(_clean_multiline(raw.draft, 4000)) if raw.draft.strip() else ""
    result["hypotheses"] = hypotheses
    result["draft"] = f"{DRAFT_HEADER}\n\n{draft}" if draft else None
    result["origin"] = "model"
    return result
