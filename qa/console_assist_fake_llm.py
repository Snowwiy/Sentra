"""Fase 7C: servidor OpenAI-compatible SIMULADO para probar el asistente sin modelo real.

Solo escucha en 127.0.0.1 y solo sirve para QA. Reproduce lo que hacen los modelos
open-weight y que Sentra tiene que tolerar o rechazar:

- un bloque de razonamiento <think>…</think> antes de la respuesta (debe desaparecer);
- prosa alrededor del JSON y el JSON dentro de un bloque ```json``` (debe interpretarse);
- una hipótesis con una referencia inventada (R99) que Sentra debe descartar con aviso.

Uso (Windows o Linux, solo biblioteca estándar):

    python qa/console_assist_fake_llm.py --port 8899

y la API de QA con:

    AI_ENABLED=true
    AI_BASE_URL=http://127.0.0.1:8899/v1
    AI_MODEL=qwen-local-test

`--mode plain` responde JSON limpio sin razonamiento; `--mode broken` responde algo que no es
JSON (Sentra debe devolver ai_invalid_response y no probar otro proveedor).

`--mode llamacpp` (7C-Fix2) imita a llama.cpp con un modelo "thinking": sin
`reasoning_effort="none"` en la petición devuelve el razonamiento en `reasoning_content`,
`content` vacío y `finish_reason="length"` (Sentra: ai_invalid_response con motivo
`truncated_reasoning`); con `AI_REASONING_EFFORT=none` responde JSON limpio.
"""

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

MODEL = "qwen-local-test"


def answer(messages: list[dict[str, Any]]) -> dict[str, Any]:
    text = " ".join(str(m.get("content", "")) for m in messages)
    # Las referencias que Sentra puso en el documento de datos: el simulador cita las reales.
    refs = sorted(set(re.findall(r'"([RADVIT]\d+)"', text)))
    tools = [r for r in refs if r.startswith("R")][:2] or refs[:1]
    assets = [r for r in refs if r.startswith("A")][:1]
    return {
        "summary": "Los resultados elegidos describen el perfil y la exposición del equipo; "
        "no muestran por sí solos un compromiso.",
        "assessment": "Lectura del simulador de QA sobre los resultados citados.",
        "confidence_note": "Media: solo se dispone de los resultados elegidos.",
        "key_findings": [
            {
                "text": "La herramienta devolvió el perfil del activo.",
                "certainty": "observed",
                "evidence": tools,
            }
        ],
        "recommended_actions": [
            {"text": "Revisar los puertos expuestos del activo.", "evidence": assets or tools}
        ],
        "limitations": ["Solo se analizaron los resultados elegidos."],
        "hypotheses": [
            {
                "text": "La exposición podría deberse a un servicio de administración olvidado.",
                "evidence": tools,
                "validate_with": "Comprobar con exposure.ports y con el responsable del equipo.",
            },
            # Inventada: Sentra debe descartarla y avisar.
            {"text": "Hipótesis sin datos reales", "evidence": ["R99"], "validate_with": "-"},
        ],
        "draft": "Revisado el perfil del activo. Pendiente validar la exposición con su responsable.",
        "evidence_refs": tools + assets,
    }


class Handler(BaseHTTPRequestHandler):
    mode = "thinking"

    def log_message(self, *args: Any) -> None:  # silencio: es una herramienta de QA
        return

    def _send(self, body: dict[str, Any]) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # /v1/models para el health check
        self._send({"object": "list", "data": [{"id": MODEL, "object": "model"}]})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        payload = json.dumps(answer(request.get("messages", [])), ensure_ascii=False)
        if self.mode == "llamacpp" and request.get("reasoning_effort") != "none":
            message = {"role": "assistant", "content": "", "reasoning_content": "pensando " * 300}
            self._send(
                {
                    "id": "qa",
                    "object": "chat.completion",
                    "model": MODEL,
                    "choices": [{"index": 0, "message": message, "finish_reason": "length"}],
                    "usage": {"completion_tokens": request.get("max_tokens")},
                }
            )
            return
        if self.mode in ("plain", "llamacpp"):
            content = payload
        elif self.mode == "broken":
            content = "Lo siento, no puedo responder en JSON."
        else:
            content = (
                "<think>razonamiento interno que Sentra no debe mostrar ni guardar</think>\n"
                f"Aquí tienes el análisis:\n```json\n{payload}\n```"
            )
        self._send(
            {
                "id": "qa",
                "object": "chat.completion",
                "model": MODEL,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
            }
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--mode", choices=["thinking", "plain", "broken", "llamacpp"], default="thinking")
    args = parser.parse_args()
    Handler.mode = args.mode
    print(f"Simulador OpenAI-compatible en http://127.0.0.1:{args.port}/v1 (modo {args.mode})")
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
