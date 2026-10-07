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
    "Readiness": "ReadinessRead",
    "DashboardAssets": "DashboardAssets",
    "DashboardRisk": "DashboardRisk",
    "DashboardIncidents": "DashboardIncidents",
    "DashboardDetections": "DashboardDetections",
    "DashboardSummary": "DashboardSummary",
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
    "DiscoveryScope": "DiscoveryScopeRead",
    "DiscoveryJob": "DiscoveryJobRead",
    "DiscoveryJobList": "DiscoveryJobList",
    "PortProcess": "PortProcess",
    "ExposedPort": "ExposedPort",
    "AgentListener": "AgentListener",
    "Exposure": "ExposureRead",
    "Agent": "AgentRead",
    "AgentSummary": "AgentSummary",
    "AgentList": "AgentList",
    "EnrollmentToken": "EnrollmentTokenRead",
    "EnrollmentTokenList": "EnrollmentTokenList",
    "ConsoleInfo": "ConsoleInfo",
    "CurrentUser": "CurrentUser",
    "AuthState": "AuthState",
    "User": "UserRead",
    "UserList": "UserList",
    "AuditEvent": "AuditEventRead",
    "AuditEventList": "AuditEventList",
    "DiscoveryNetwork": "DiscoveryNetworkRead",
    "DiscoveryProgress": "DiscoveryProgressRead",
    "DiscoveryAssetRef": "DiscoveryAssetRef",
    "DiscoveryChange": "DiscoveryChangeRead",
    "DiscoveryJobDetail": "DiscoveryJobDetail",
    "DiscoverySchedule": "DiscoveryScheduleRead",
    "ClassificationEvidence": "ClassificationEvidence",
    "Detection": "DetectionRead",
    "DetectionList": "DetectionList",
    "DetectionEvidence": "DetectionEvidenceRead",
    "DetectionDetail": "DetectionDetail",
    "DetectionRule": "DetectionRuleRead",
    "DetectionRuleList": "DetectionRuleList",
    "RiskContribution": "RiskContributionRead",
    "RiskExplanationItem": "RiskExplanationItem",
    "ConfidenceFactor": "ConfidenceFactorRead",
    "RiskExplanation": "RiskExplanation",
    "RiskAssetSummary": "RiskAssetSummary",
    "RiskAssetList": "RiskAssetList",
    "RiskFactor": "RiskFactorRead",
    "RiskSnapshot": "RiskSnapshotRead",
    "RiskTransition": "RiskTransitionRead",
    "RiskLevelRange": "RiskLevelRange",
    "RiskOverview": "RiskOverview",
    "RiskDetectionRef": "RiskDetectionRef",
    "RiskAssetDetail": "RiskAssetDetail",
    "RiskHistory": "RiskHistory",
    "RiskContributionList": "RiskContributionList",
    # Fase 4J: AI Security Insights.
    "EvidenceRef": "EvidenceRefRead",
    "InsightFinding": "InsightFinding",
    "InsightAction": "InsightAction",
    "InsightResult": "InsightResult",
    "Insight": "InsightRead",
    "InsightList": "InsightList",
    "AIStatus": "AIStatus",
    # Fase 4J.2: gestor de modelos locales.
    "LocalCPU": "CPURead",
    "LocalGPU": "GPURead",
    "LocalHardware": "HardwareRead",
    "LocalRuntimeCapabilities": "RuntimeCapabilitiesRead",
    "LocalActiveModel": "ActiveModelRead",
    "LocalRuntimeStatus": "RuntimeStatusRead",
    "LocalBenchmark": "BenchmarkRead",
    "LocalModel": "LocalModelRead",
    "DiscoveredModel": "DiscoveredModelRead",
    "LocalModelList": "LocalModelList",
    "ModelEstimate": "EstimateRead",
    "ModelRecommendation": "RecommendationRead",
    "RecommendationList": "RecommendationList",
    "LocalModelDetail": "LocalModelDetail",
    # Fase 4K: gestión de incidentes.
    "IncidentUserRef": "IncidentUserRef",
    "IncidentLink": "IncidentLink",
    "IncidentAssetRef": "IncidentAssetRef",
    "IncidentSummary": "IncidentSummary",
    "IncidentList": "IncidentList",
    "IncidentDetectionRef": "IncidentDetectionRef",
    "IncidentAlertRef": "IncidentAlertRef",
    "IncidentRiskAsset": "IncidentRiskAsset",
    "IncidentRiskSnapshot": "IncidentRiskSnapshot",
    "IncidentRiskContext": "IncidentRiskContext",
    "IncidentMetrics": "IncidentMetrics",
    "IncidentDetail": "IncidentDetail",
    "IncidentNote": "IncidentNoteRead",
    "IncidentNoteList": "IncidentNoteList",
    "TimelineItem": "TimelineItem",
    "IncidentTimeline": "IncidentTimeline",
    "EvidenceEvent": "EvidenceEventRead",
    "EvidenceExposure": "EvidenceExposureRead",
    "EvidenceRisk": "EvidenceRiskRead",
    "IncidentEvidence": "IncidentEvidence",
    "RelatedIncident": "RelatedIncident",
    "RelatedIncidentList": "RelatedIncidentList",
    "IncidentActivity": "IncidentActivityRead",
    "IncidentOverview": "IncidentOverview",
    "AssignableUser": "AssignableUser",
    "AssignableUserList": "AssignableUserList",
    "IncidentAuditEvent": "IncidentAuditEvent",
    "IncidentAuditList": "IncidentAuditList",
    # Fase 4L: Asset Context.
    "FieldProvenance": "FieldProvenance",
    "RoleSuggestion": "RoleSuggestion",
    "ContextCompleteness": "ContextCompleteness",
    "AssetContext": "AssetContextRead",
    "AssetContextBrief": "AssetContextBrief",
    "AssetContextSnapshot": "AssetContextSnapshot",
    "AssetContextChange": "AssetContextChangeRead",
    "AssetContextHistory": "AssetContextHistory",
    "ContextLimits": "ContextLimits",
    "AssetContextOptions": "AssetContextOptions",
    "ThreatRisk": "ThreatRisk",
    "AssetThreatSummary": "AssetThreatSummary",
    # Fase 5A: reglas personalizadas y Sigma.
    "RuleIssue": "RuleIssue",
    "RuleStats": "RuleStatsRead",
    "RuleDetail": "RuleDetail",
    "RuleVersion": "RuleVersionRead",
    "RuleVersionList": "RuleVersionList",
    "RuleVersionDetail": "RuleVersionDetail",
    "RuleChange": "RuleChange",
    "RuleDiff": "RuleDiff",
    "RuleValidation": "RuleValidation",
    "EventTestResult": "EventTestResult",
    "SimulatedDetection": "SimulatedDetection",
    "RuleTestResult": "RuleTestResult",
    "HistoricalMatch": "HistoricalMatch",
    "HistoricalGroup": "HistoricalGroup",
    "HistoricalTestResult": "HistoricalTestResult",
    "SigmaSource": "SigmaSource",
    "SigmaDuplicate": "SigmaDuplicate",
    "SigmaPreview": "SigmaPreview",
    "SigmaImportResult": "SigmaImportResult",
    "RuleField": "FieldRead",
    "RuleLogSource": "LogSourceRead",
    "RuleCompatibility": "CompatibilityRead",
    "RuleCatalog": "RuleCatalog",
    # Fase 5B: vulnerabilidades y exposición.
    "DashboardVulnerabilities": "DashboardVulnerabilities",
    "IncidentVulnerabilityRef": "IncidentVulnerabilityRef",
    "VulnerabilityAssetRef": "VulnerabilityAssetRef",
    "FindingSummary": "FindingSummary",
    "FindingList": "FindingList",
    "CatalogRecordRef": "CatalogRecordRef",
    "FindingIncidentRef": "FindingIncidentRef",
    "FindingDetail": "FindingDetail",
    "FindingHistoryItem": "FindingHistoryItem",
    "FindingHistory": "FindingHistory",
    "VulnerabilityOverview": "VulnerabilityOverview",
    "AssetVulnerabilityStatus": "AssetVulnerabilityStatus",
    "AssetVulnerabilities": "AssetVulnerabilities",
    "CatalogSource": "CatalogSourceRead",
    "CatalogRecordSummary": "CatalogRecordSummary",
    "CatalogList": "CatalogList",
    "CatalogInvalidRecord": "CatalogInvalidRecord",
    "CatalogPreview": "CatalogPreview",
    "CatalogImportResult": "CatalogImportResult",
    "EvaluateResult": "EvaluateResult",
    "ExposureVulnerabilityRef": "ExposureVulnerabilityRef",
    "ExposureItem": "ExposureItem",
    "ExposureOverview": "ExposureOverview",
    # Fase 5C: Threat Intelligence.
    "ThreatSource": "ThreatSourceRead",
    "ThreatSourceList": "ThreatSourceList",
    "ThreatSync": "ThreatSyncRead",
    "ThreatSyncList": "ThreatSyncList",
    "ThreatChange": "ThreatChangeRead",
    "ThreatIntelOverview": "ThreatIntelOverview",
    "IndicatorSourceRef": "IndicatorSourceRef",
    "IndicatorSummary": "IndicatorSummary",
    "IndicatorList": "IndicatorList",
    "IndicatorDetail": "IndicatorDetail",
    "ThreatMatchSummary": "MatchSummary",
    "ThreatMatchList": "MatchList",
    "ThreatMatchDetail": "MatchDetail",
    "ThreatInvalidRecord": "ThreatInvalidRecord",
    "ThreatImportPreview": "ThreatImportPreview",
    "ThreatImportResult": "ThreatImportResult",
    "IntelSourceRef": "IntelSourceRef",
    "KevIntel": "KevIntel",
    "EpssIntel": "EpssIntel",
    "FindingThreatIntel": "FindingThreatIntel",
    "IncidentThreatMatchRef": "IncidentThreatMatchRef",
}
ENUMS = [
    "AssetStatus",
    "AlertRule",
    "AlertSeverity",
    "AlertStatus",
    "EventLevel",
    "ChangeCategory",
    "ChangeKind",
    "MonitoringMethod",
    "DiscoveryJobStatus",
    "DiscoveryTrigger",
    "PortStateValue:PortState",
    "CredentialStatus",
    "EnrollmentTokenState",
    "ClassificationConfidence",
    "DetectionSeverity",
    "DetectionConfidence",
    "DetectionStatus",
    "RiskLevel",
    "RiskConfidence",
    "AssetCriticality",
    "IncidentStatus",
    "IncidentLevel",
    "IncidentConfidence",
    "ResolutionCategory",
    "AssetRole",
    "AssetEnvironment",
    "DataSensitivity",
    "NetworkZone",
]


def _typescript() -> str:
    if not TYPES_TS.exists():
        pytest.skip("frontend sources not available")
    return TYPES_TS.read_text(encoding="utf-8")


def _interface_fields(source: str, name: str) -> set[str]:
    match = re.search(
        rf"export interface {name}(?: extends (\w+))? \{{(.*?)\n\}}", source, re.DOTALL
    )
    assert match, f"interface {name} not found in types.ts"
    fields = set(re.findall(r"^\s+(\w+)\??:", match.group(2), re.MULTILINE))
    # `interface A extends B`: los campos heredados también forman parte del contrato.
    return fields | (_interface_fields(source, match.group(1)) if match.group(1) else set())


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
    # "Schema:TsType" when the TypeScript name differs from the API schema name.
    schema, _, ts_name = name.partition(":")
    assert _enum_values(_typescript(), ts_name or schema) == _schema(schemas, schema)["enum"]


def test_created_token_is_the_listed_token_plus_the_value(schemas: dict[str, Any]) -> None:
    # `EnrollmentTokenCreated extends EnrollmentToken` in types.ts adds only `token`.
    source = _typescript()
    match = re.search(
        r"export interface EnrollmentTokenCreated extends EnrollmentToken \{(.*?)\n\}",
        source,
        re.DOTALL,
    )
    assert match
    assert set(re.findall(r"^\s+(\w+)\??:", match.group(1), re.MULTILINE)) == {"token"}
    created = set(_schema(schemas, "EnrollmentTokenCreated")["properties"])
    assert created == set(_schema(schemas, "EnrollmentTokenRead")["properties"]) | {"token"}


def test_permissions_match_the_backend() -> None:
    # Un permiso nuevo (como ai:use en la Fase 4J) debe existir también en la UI.
    from app.core.permissions import Permission

    assert set(_enum_values(_typescript(), "Permission")) == {p.value for p in Permission}
