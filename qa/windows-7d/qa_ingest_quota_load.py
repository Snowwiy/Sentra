"""Prueba de carga de las cuotas de ingesta (Fase 7D.2, H06) contra un servidor de LABORATORIO.

Simula varios agentes concurrentes con identidades reales (enrolados con tokens de un solo uso
creados con la clave de administración):

- un agente "ruidoso" envía lotes de eventos sin pausa;
- el resto ("sanos") envía heartbeat y un lote pequeño de eventos cada pocos segundos.

Comprueba lo que exige H06: el ruidoso recibe 429 con Retry-After, los sanos no reciben ningún
429 de su cuota, el heartbeat del ruidoso sigue aceptado (control) y reenviar un lote ya
aceptado no duplica nada (201 con stored = 0).

Solo biblioteca estándar. Nunca imprime tokens. Uso (PowerShell, desde la raíz del repo):

    $s = Read-Host "Clave admin del LABORATORIO" -AsSecureString
    $env:SENTRA_ADMIN_KEY = [System.Net.NetworkCredential]::new("", $s).Password
    py qa\\windows-7d\\qa_ingest_quota_load.py --server https://sentra-lab.lan --ca-file ca.pem `
        --healthy 4 --seconds 60

Deja N activos "qa7d2-*" en el servidor: archivarlos después desde la consola. NO usar contra
el servidor productivo.
"""

import argparse
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

API = "/api/v1"


class Client:
    def __init__(self, server: str, ca_file: str | None) -> None:
        # Solo http(s): urllib también abriría file:// u otros esquemas.
        if not server.startswith(("https://", "http://")):
            raise SystemExit("--server debe empezar por https:// (o http:// a loopback)")
        self.base = server.rstrip("/") + API
        self.context = ssl.create_default_context(cafile=ca_file) if ca_file else None

    def call(
        self, path: str, body: dict[str, Any] | None, headers: dict[str, str]
    ) -> tuple[int, dict[str, Any], str | None]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310  (esquema comprobado en __init__)
            self.base + path,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json", **headers},
        )
        try:
            with urllib.request.urlopen(request, timeout=30, context=self.context) as response:  # noqa: S310
                return response.status, json.loads(response.read() or b"{}"), None
        except urllib.error.HTTPError as error:
            with error:
                raw = error.read()
                retry_after = error.headers.get("Retry-After")
            try:
                payload = json.loads(raw or b"{}")
            except ValueError:
                payload = {}
            return error.code, payload, retry_after


def host(name: str, agent_id: str) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "hostname": name,
        "os_name": "Windows",
        "os_version": "11 Pro 24H2",
        "architecture": "x86_64",
        "primary_ip": "192.0.2.10",
        "agent_version": "0.7.1",
    }


def events(agent_id: str, start: int, count: int) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    return {
        "agent_id": agent_id,
        "events": [
            {
                "source": "windows_eventlog",
                "channel": "Application",
                "record_id": start + i,
                "event_code": 1000,
                "provider": "qa7d2",
                "level": "warning",
                "message": "evento sintetico de carga 7D.2",
                "occurred_at": now,
            }
            for i in range(count)
        ],
    }


class Agent:
    def __init__(self, client: Client, name: str, token: str) -> None:
        self.client = client
        self.name = name
        self.agent_id = str(uuid.uuid4())
        status, body, _ = client.call(
            "/agents/register", host(name, self.agent_id), {"X-Enrollment-Token": token}
        )
        if status != 201 and status != 200:
            code = (body.get("error") or {}).get("code")
            raise SystemExit(f"registro de {name} fallido: HTTP {status} {code}")
        self.auth = {"Authorization": f"Bearer {body['agent_token']}"}
        self.results: Counter[str] = Counter()
        self.retry_after: list[int] = []
        self.next_record = 1

    def send(self, path: str, body: dict[str, Any], label: str) -> tuple[int, dict[str, Any]]:
        status, payload, retry_after = self.client.call(path, body, self.auth)
        self.results[f"{label}:{status}"] += 1
        if status == 429:
            error = payload.get("error") or {}
            reason = (error.get("details") or [{}])[0].get("reason", "?")
            self.results[f"{label}:429:{reason}"] += 1
            if retry_after is None:
                self.results[f"{label}:429:missing_retry_after"] += 1
            else:
                self.retry_after.append(int(retry_after))
        return status, payload


def run_noisy(agent: Agent, stop: threading.Event, batch: int) -> None:
    while not stop.is_set():
        status, _ = agent.send(
            "/events", events(agent.agent_id, agent.next_record, batch), "events"
        )
        if status in (200, 201):
            agent.next_record += batch
        # El ruidoso no respeta Retry-After a propósito: es el agente abusivo.


def run_healthy(agent: Agent, stop: threading.Event, interval: float) -> None:
    while not stop.is_set():
        agent.send("/agents/heartbeat", {"agent_id": agent.agent_id}, "heartbeat")
        status, _ = agent.send("/events", events(agent.agent_id, agent.next_record, 5), "events")
        if status in (200, 201):
            agent.next_record += 5
        stop.wait(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--server", required=True, help="URL del servidor de laboratorio")
    parser.add_argument("--ca-file", help="CA interna en PEM si el certificado no es público")
    parser.add_argument("--healthy", type=int, default=4, help="agentes sanos (4)")
    parser.add_argument("--seconds", type=float, default=60.0, help="duración (60)")
    parser.add_argument("--batch", type=int, default=500, help="eventos por lote del ruidoso")
    parser.add_argument("--interval", type=float, default=5.0, help="pausa de los sanos (5 s)")
    args = parser.parse_args()

    admin_key = os.environ.get("SENTRA_ADMIN_KEY")
    if not admin_key:
        print("Falta SENTRA_ADMIN_KEY en el entorno (no se acepta por argumento).")
        return 2
    client = Client(args.server, args.ca_file)
    status, body, _ = client.call(
        "/agent-enrollment-tokens",
        {"max_uses": args.healthy + 1, "ttl_minutes": 30, "note": "QA 7D.2 carga de cuotas"},
        {"X-Admin-Key": admin_key},
    )
    if status != 201:
        code = (body.get("error") or {}).get("code")
        print(f"No se pudo crear el token de enrolamiento: HTTP {status} {code}")
        return 2
    token = body["token"]
    stamp = datetime.now(UTC).strftime("%H%M%S")
    noisy = Agent(client, f"qa7d2-{stamp}-noisy", token)
    healthy = [Agent(client, f"qa7d2-{stamp}-ok{i}", token) for i in range(args.healthy)]
    del token

    stop = threading.Event()
    threads = [threading.Thread(target=run_noisy, args=(noisy, stop, args.batch))]
    threads += [
        threading.Thread(target=run_healthy, args=(agent, stop, args.interval)) for agent in healthy
    ]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    # Heartbeats del ruidoso durante la saturación: la clase control no comparte su cupo.
    while time.monotonic() - started < args.seconds:
        time.sleep(5)
        noisy.send("/agents/heartbeat", {"agent_id": noisy.agent_id}, "heartbeat")
    stop.set()
    for thread in threads:
        thread.join()

    # Reenvío de un lote ya aceptado de un agente sano: debe dar 201 con stored = 0.
    sample = healthy[0] if healthy else noisy
    resend_status, resend_body = sample.send("/events", events(sample.agent_id, 1, 5), "resend")

    checks = {
        "ruidoso_recibe_429": noisy.results["events:429"] > 0,
        "429_siempre_con_retry_after": all(
            agent.results.get(key, 0) == 0
            for agent in [noisy, *healthy]
            for key in ("events:429:missing_retry_after", "heartbeat:429:missing_retry_after")
        ),
        "heartbeat_del_ruidoso_aceptado": noisy.results["heartbeat:200"] > 0
        and noisy.results["heartbeat:429:agent_requests"] == 0,
        "sanos_sin_429_de_cuota_propia": all(
            sum(n for k, n in agent.results.items() if k.startswith("events:429:agent_")) == 0
            for agent in healthy
        ),
        "reenvio_sin_duplicados": resend_status in (200, 201) and resend_body.get("stored") == 0,
    }
    report = {
        "noisy": {
            "results": dict(noisy.results),
            "retry_after_max": max(noisy.retry_after, default=None),
        },
        "healthy": [dict(agent.results) for agent in healthy],
        "checks": checks,
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    # Un 429 global en un sano no es fallo de la prueba si el laboratorio tiene límites globales
    # bajos: aparece en el informe como events:429:global_* para revisarlo a mano.
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
