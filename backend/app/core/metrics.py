"""Métricas técnicas en formato de texto de Prometheus, sin dependencias (Fase 4M).

Registro en memoria del proceso para lo que ocurre en él (peticiones HTTP, ejecuciones de
jobs, rechazos por rate limit). Lo que vive en la base (activos, agentes, detecciones,
incidentes, colas) se calcula con consultas agregadas al pedir /metrics y es global.

Reglas de etiquetas: cardinalidad acotada y nada sensible. La ruta es la plantilla de
FastAPI (/api/v1/assets/{asset_id}), nunca la URL real; no hay hostnames, usuarios, IPs ni
tokens como etiqueta. Con varios workers cada uno expone sus contadores de proceso (lo
normal en Prometheus: sumar por instancia); los valores de base de datos son iguales en
todos.
"""

import threading
import time
from collections import defaultdict
from collections.abc import Iterable

# Límites (segundos) del histograma de latencia: de una lectura simple a una llamada a la IA.
LATENCY_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(pairs: Iterable[tuple[str, str]]) -> str:
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in pairs)
    return "{" + inner + "}" if inner else ""


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = time.time()
        self._requests: dict[tuple[str, str, str], int] = defaultdict(int)
        self._latency: dict[str, list[int]] = {}
        self._latency_sum: dict[str, float] = defaultdict(float)
        self._latency_count: dict[str, int] = defaultdict(int)
        self._jobs: dict[tuple[str, str], int] = defaultdict(int)
        self._job_last: dict[str, tuple[float, float]] = {}
        self._rate_limited: dict[str, int] = defaultdict(int)
        # Fase 5A: evaluaciones de reglas por ORIGEN (builtin, custom, sigma). Nunca por regla:
        # con cientos de reglas personalizadas la cardinalidad se dispararía; el detalle por
        # regla está en GET /detection-rules (detection_rule_stats).
        self._rules: dict[str, list[float]] = {}
        # Fase 5B: totales de la evaluación de vulnerabilidades por RESULTADO (created,
        # resolved...). Nunca por CVE ni por activo: la cardinalidad sería ilimitada.
        self._vulns: dict[str, int] = defaultdict(int)
        self._vuln_seconds = 0.0

    def observe_request(self, method: str, route: str, status: int, seconds: float) -> None:
        status_class = f"{status // 100}xx"
        with self._lock:
            self._requests[(method, route, status_class)] += 1
            buckets = self._latency.setdefault(route, [0] * len(LATENCY_BUCKETS))
            for i, bound in enumerate(LATENCY_BUCKETS):
                if seconds <= bound:
                    buckets[i] += 1
            self._latency_sum[route] += seconds
            self._latency_count[route] += 1

    def observe_job(self, job: str, result: str, seconds: float) -> None:
        with self._lock:
            self._jobs[(job, result)] += 1
            if result == "success":
                self._job_last[job] = (time.time(), seconds)

    def observe_rules(
        self, source: str, evaluations: int, matches: int, errors: int, seconds: float
    ) -> None:
        with self._lock:
            totals = self._rules.setdefault(source, [0, 0, 0, 0.0])
            totals[0] += evaluations
            totals[1] += matches
            totals[2] += errors
            totals[3] += seconds

    def observe_vulnerabilities(self, totals: dict[str, int], seconds: float) -> None:
        with self._lock:
            for outcome, count in totals.items():
                self._vulns[outcome] += count
            self._vuln_seconds += seconds

    def rate_limited(self, scope: str) -> None:
        with self._lock:
            self._rate_limited[scope] += 1

    def render(self) -> list[str]:
        lines: list[str] = []
        with self._lock:
            lines += [
                "# HELP sentra_process_start_time_seconds Inicio del proceso (epoch).",
                "# TYPE sentra_process_start_time_seconds gauge",
                f"sentra_process_start_time_seconds {self.started:.0f}",
                "# HELP sentra_http_requests_total Peticiones HTTP por ruta y clase de estado.",
                "# TYPE sentra_http_requests_total counter",
            ]
            for (method, route, status), count in sorted(self._requests.items()):
                labels = _labels((("method", method), ("route", route), ("status", status)))
                lines.append(f"sentra_http_requests_total{labels} {count}")
            lines += [
                "# HELP sentra_http_request_duration_seconds Latencia por ruta.",
                "# TYPE sentra_http_request_duration_seconds histogram",
            ]
            for route, buckets in sorted(self._latency.items()):
                for bound, count in zip(LATENCY_BUCKETS, buckets, strict=True):
                    labels = _labels((("route", route), ("le", str(bound))))
                    lines.append(f"sentra_http_request_duration_seconds_bucket{labels} {count}")
                total = self._latency_count[route]
                inf = _labels((("route", route), ("le", "+Inf")))
                lines.append(f"sentra_http_request_duration_seconds_bucket{inf} {total}")
                route_label = _labels((("route", route),))
                lines.append(
                    f"sentra_http_request_duration_seconds_sum{route_label}"
                    f" {self._latency_sum[route]:.6f}"
                )
                lines.append(f"sentra_http_request_duration_seconds_count{route_label} {total}")
            lines += [
                "# HELP sentra_job_runs_total Ejecuciones de jobs periódicos por resultado.",
                "# TYPE sentra_job_runs_total counter",
            ]
            for (job, result), count in sorted(self._jobs.items()):
                labels = _labels((("job", job), ("result", result)))
                lines.append(f"sentra_job_runs_total{labels} {count}")
            lines += [
                "# HELP sentra_job_last_success_timestamp_seconds Último éxito de cada job.",
                "# TYPE sentra_job_last_success_timestamp_seconds gauge",
            ]
            for job, (at, _) in sorted(self._job_last.items()):
                labels = _labels((("job", job),))
                lines.append(f"sentra_job_last_success_timestamp_seconds{labels} {at:.0f}")
            lines += [
                "# HELP sentra_job_last_duration_seconds Duración del último éxito de cada job.",
                "# TYPE sentra_job_last_duration_seconds gauge",
            ]
            for job, (_, seconds) in sorted(self._job_last.items()):
                labels = _labels((("job", job),))
                lines.append(f"sentra_job_last_duration_seconds{labels} {seconds:.3f}")
            lines += [
                "# HELP sentra_rate_limited_total Peticiones rechazadas con 429 por ámbito.",
                "# TYPE sentra_rate_limited_total counter",
            ]
            for scope, count in sorted(self._rate_limited.items()):
                lines.append(f"sentra_rate_limited_total{_labels((('scope', scope),))} {count}")
            for index, (name, help_text) in enumerate(
                (
                    ("sentra_detection_rule_evaluations_total", "Evaluaciones de reglas."),
                    ("sentra_detection_rule_matches_total", "Coincidencias de reglas."),
                    ("sentra_detection_rule_errors_total", "Errores aislados de reglas."),
                    (
                        "sentra_detection_rule_evaluation_seconds_total",
                        "Tiempo total evaluando reglas.",
                    ),
                )
            ):
                lines += [f"# HELP {name} {help_text} Por origen.", f"# TYPE {name} counter"]
                for source, totals in sorted(self._rules.items()):
                    value = totals[index]
                    shown = f"{value:.6f}" if index == 3 else f"{int(value)}"
                    lines.append(f"{name}{_labels((('source', source),))} {shown}")
            lines += [
                "# HELP sentra_vulnerability_evaluations_total Resultados de la evaluación de"
                " vulnerabilidades (activos, findings creados, resueltos...).",
                "# TYPE sentra_vulnerability_evaluations_total counter",
            ]
            for outcome, count in sorted(self._vulns.items()):
                labels = _labels((("outcome", outcome),))
                lines.append(f"sentra_vulnerability_evaluations_total{labels} {count}")
            lines += [
                "# HELP sentra_vulnerability_evaluation_seconds_total Tiempo total evaluando.",
                "# TYPE sentra_vulnerability_evaluation_seconds_total counter",
                f"sentra_vulnerability_evaluation_seconds_total {self._vuln_seconds:.6f}",
            ]
        return lines


def gauge(name: str, help_text: str, values: Iterable[tuple[dict[str, str], float]]) -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
    for labels, value in values:
        lines.append(f"{name}{_labels(sorted(labels.items()))} {value:g}")
    return lines


# Un registro por proceso.
REGISTRY = MetricsRegistry()
