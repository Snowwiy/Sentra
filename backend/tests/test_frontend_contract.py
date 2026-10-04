"""The dashboard's TypeScript types must match the API's response schemas.

`frontend/src/api/types.ts` mirrors the backend schemas by hand. When they drift (a renamed
field, a new alert rule or event level) TypeScript cannot notice, because the data comes from
the network: the UI just renders blanks. This compares field names and enum values with the
OpenAPI document the API itself generates.
"""

import re
from pathlib import Path
from typing import Any

import pytest

from app.main import create_app

TYPES_TS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "api" / "types.ts"

# TypeScript interface -> OpenAPI schema (response models only).
INTERFACES = {
    "Asset": "AssetRead",
    "AssetList": "AssetList",
    "TelemetrySnapshot": "TelemetrySnapshot",
    "TelemetryHistory": "TelemetryHistory",
    "Health": "HealthRead",
    "Alert": "AlertRead",
    "AlertList": "AlertList",
    "SystemEvent": "EventRead",
    "EventList": "EventList",
    "Inventory": "InventoryRead",
    "NetworkInterface": "NetworkInterface",
    "LoggedInUser": "LoggedInUser",
    "ProcessInfo": "ProcessInfo",
    "ServiceInfo": "ServiceInfo",
    "SoftwareInfo": "SoftwareInfo",
    "DiskInfo": "DiskInfo",
    "NetworkConnection": "NetworkConnection",
    "ApiErrorBody": "ErrorBody",
    "AccountInfo": "AccountInfo",
    "NetworkSummary": "NetworkSummary",
    "ProcessEntry": "ProcessEntry",
    "ProcessSnapshot": "ProcessSnapshotRead",
    "AssetChange": "ChangeRead",
    "ChangeList": "ChangeList",
}
ENUMS = [
    "AssetStatus",
    "AlertRule",
    "AlertSeverity",
    "AlertStatus",
    "EventLevel",
    "ChangeCategory",
    "ChangeKind",
]


def _typescript() -> str:
    if not TYPES_TS.exists():
        pytest.skip("frontend sources not available")
    return TYPES_TS.read_text(encoding="utf-8")


def _interface_fields(source: str, name: str) -> set[str]:
    match = re.search(rf"export interface {name} \{{(.*?)\n\}}", source, re.DOTALL)
    assert match, f"interface {name} not found in types.ts"
    return set(re.findall(r"^\s+(\w+)\??:", match.group(1), re.MULTILINE))


def _enum_values(source: str, name: str) -> list[str]:
    match = re.search(rf"export type {name} =\s*([^;]+);", source)
    assert match, f"type {name} not found in types.ts"
    return re.findall(r'"([^"]+)"', match.group(1))


@pytest.fixture(scope="module")
def schemas() -> dict[str, Any]:
    components: dict[str, Any] = create_app().openapi()["components"]["schemas"]
    return components


def _schema(schemas: dict[str, Any], name: str) -> dict[str, Any]:
    # FastAPI suffixes models used both as input and output; the dashboard reads outputs.
    found: dict[str, Any] | None = schemas.get(f"{name}-Output") or schemas.get(name)
    assert found is not None, f"schema {name} not in the OpenAPI document"
    return found


@pytest.mark.parametrize(("interface", "schema"), INTERFACES.items())
def test_interface_fields_match_the_response_schema(
    schemas: dict[str, Any], interface: str, schema: str
) -> None:
    api_fields = set(_schema(schemas, schema)["properties"])

    assert _interface_fields(_typescript(), interface) == api_fields


@pytest.mark.parametrize("name", ENUMS)
def test_enum_values_match(schemas: dict[str, Any], name: str) -> None:
    assert _enum_values(_typescript(), name) == _schema(schemas, name)["enum"]
