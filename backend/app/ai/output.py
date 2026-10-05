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
from app.ai.provider import AIInvalidResponseError, AIUngroundedResponseError
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


def parse_json(content: str) -> RawInsight:
    """JSON del modelo -> RawInsight, o AIInvalidResponseError (nunca se evalúa nada)."""
    text = content.strip()
    # Algunos modelos envuelven el JSON en un bloque ```json ... ``` pese a la instrucción.
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        data = json.loads(text)
    except ValueError:
        raise AIInvalidResponseError("The AI response is not valid JSON") from None
    if not isinstance(data, dict):
        raise AIInvalidResponseError("The AI response is not a JSON object")
    try:
        return RawInsight.model_validate(data)
    except ValidationError:
        raise AIInvalidResponseError("The AI response does not match the expected format") from None


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
    for section in ("active_detections", "detection", "detections_in_window"):
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
