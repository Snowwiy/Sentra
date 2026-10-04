from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.schemas.common import ErrorResponse
from tests.conftest import agent_payload


def test_valid_request_id_is_echoed(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"X-Request-ID": "dash-01:poll.7_a"})

    assert response.headers["X-Request-ID"] == "dash-01:poll.7_a"


@pytest.mark.parametrize("value", ["has space", "x" * 129, "<script>", "a;b", ""])
def test_untrusted_request_id_is_replaced(client: TestClient, value: str) -> None:
    # The id is copied into every log line of the request: odd or huge values are not trusted.
    response = client.get("/api/v1/health", headers={"X-Request-ID": value})

    echoed = response.headers["X-Request-ID"]
    assert echoed != value
    UUID(echoed)  # a fresh server-generated id instead


def _assert_security_headers(headers: Any) -> None:
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"


def test_security_headers_on_success_and_error_responses(client: TestClient) -> None:
    _assert_security_headers(client.get("/api/v1/health").headers)
    _assert_security_headers(client.get(f"/api/v1/assets/{uuid4()}").headers)  # 404
    _assert_security_headers(client.get("/api/v1/assets/not-a-uuid").headers)  # 422


def test_enrollment_response_with_token_is_not_cacheable(client: TestClient) -> None:
    response = client.post("/api/v1/agents/register", json=agent_payload())

    assert response.status_code == 201
    assert response.json()["agent_token"]
    _assert_security_headers(response.headers)


def test_oversized_body_rejection_has_security_headers(client: TestClient) -> None:
    limit = get_settings().max_request_bytes

    response = client.post(
        "/api/v1/events",
        content=b"x" * (limit + 1),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    _assert_security_headers(response.headers)


def _documented(spec: dict[str, Any], method: str, path: str) -> dict[str, str]:
    """Status code -> schema name of every documented response of one route."""
    responses = spec["paths"][f"/api/v1{path}"][method]["responses"]
    return {
        status: body.get("content", {})
        .get("application/json", {})
        .get("schema", {})
        .get("$ref", "")
        .rsplit("/", 1)[-1]
        for status, body in responses.items()
    }


def test_openapi_documents_the_real_error_envelope(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    # FastAPI's default {"detail": [...]} model is not what the API sends.
    assert "HTTPValidationError" not in spec["components"]["schemas"]
    for path, operations in spec["paths"].items():
        for method, operation in operations.items():
            for status, body in operation["responses"].items():
                schema = body.get("content", {}).get("application/json", {}).get("schema", {})
                if int(status) >= 400 and path != "/api/v1/health":
                    assert schema["$ref"].endswith("/ErrorResponse"), (method, path, status)


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("post", "/agents/register", {"201", "200", "401", "403", "409", "413", "422", "503"}),
        ("post", "/agents/heartbeat", {"200", "401", "413", "422", "503"}),
        ("post", "/telemetry", {"201", "401", "413", "422", "503"}),
        ("post", "/inventory", {"201", "401", "413", "422", "503"}),
        ("post", "/events", {"201", "401", "413", "422", "503"}),
        ("get", "/assets/{asset_id}", {"200", "404", "422", "503"}),
        ("get", "/assets/{asset_id}/inventory", {"200", "404", "422", "503"}),
        ("get", "/alerts", {"200", "404", "422", "503"}),
        ("get", "/health", {"200", "503"}),
    ],
)
def test_openapi_lists_the_statuses_each_route_can_answer(
    client: TestClient, method: str, path: str, expected: set[str]
) -> None:
    assert set(_documented(client.get("/openapi.json").json(), method, path)) == expected


def test_re_enrollment_documents_the_same_body_as_enrollment(client: TestClient) -> None:
    documented = _documented(client.get("/openapi.json").json(), "post", "/agents/register")

    assert documented["200"] == documented["201"] == "AgentRegisterResponse"


def test_actual_validation_errors_match_the_documented_envelope(client: TestClient) -> None:
    response = client.get("/api/v1/alerts", params={"limit": 0})

    assert response.status_code == 422
    body = ErrorResponse.model_validate(response.json())
    assert body.error.code == "validation_error"
    assert body.error.details


def test_request_log_records_the_client_address(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO", logger="sentra.request"):
        client.post("/api/v1/agents/register", json=agent_payload(), headers={})

    (record,) = [r for r in caplog.records if r.name == "sentra.request"]
    assert record.status_code == 401  # type: ignore[attr-defined]
    assert record.client == "testclient"  # type: ignore[attr-defined]
