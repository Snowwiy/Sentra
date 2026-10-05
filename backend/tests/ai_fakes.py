"""FakeAIProvider determinista para los tests de la Fase 4J (sin red, sin tokens reales).

Por defecto responde un análisis "grounded" que cita las primeras referencias que encuentra
en el contexto. Cada test puede cambiar `responder` para simular JSON inválido, IDs
inventados, timeouts o caídas del proveedor. Guarda las peticiones para inspeccionar qué
habría salido del servidor.
"""

import json
from collections.abc import Callable
from typing import Any

from app.ai.openai_compat import ProviderHealth
from app.ai.provider import AIRequest, AIResponse

Responder = Callable[[AIRequest], str | Exception]


def context_refs(request: AIRequest) -> list[str]:
    """Referencias citables ("D1", "C2"...) presentes en sentra_data, en orden."""
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            ref = value.get("ref")
            if isinstance(ref, str) and ref not in found:
                found.append(ref)
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(json.loads(request.user)["sentra_data"])
    return found


def answer(
    refs: list[str],
    *,
    summary: str = "Resumen basado en datos de Sentra.",
    assessment: str = "Evaluación prudente.",
    certainty: str = "detected",
    insufficient: bool = False,
) -> str:
    return json.dumps(
        {
            "summary": summary,
            "assessment": assessment,
            "confidence_note": "Confianza según Sentra.",
            "key_findings": (
                [{"text": "Hallazgo con evidencia.", "certainty": certainty, "evidence": refs}]
                if refs
                else []
            ),
            "recommended_actions": [
                {"text": "Validar si la actividad fue autorizada.", "evidence": refs[:1]}
            ],
            "evidence_refs": refs,
            "limitations": ["Solo datos de Sentra."],
            "insufficient_data": insufficient,
        }
    )


def grounded(request: AIRequest) -> str:
    refs = context_refs(request)
    return answer(refs[:3], insufficient=not refs)


class FakeAIProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self) -> None:
        self.requests: list[AIRequest] = []
        self.responder: Responder = grounded
        # Health check simulado (4J.1): False = servidor de IA local apagado.
        self.healthy = True
        self.checks = 0

    def check(self) -> ProviderHealth:
        self.checks += 1
        if self.healthy:
            return ProviderHealth(True, 2)
        return ProviderHealth(False, 2, "The AI provider is unavailable (ConnectionRefusedError)")

    def complete(self, request: AIRequest) -> AIResponse:
        self.requests.append(request)
        result = self.responder(request)
        if isinstance(result, Exception):
            raise result
        return AIResponse(
            content=result, model=self.model, latency_ms=3, usage_input=100, usage_output=50
        )
