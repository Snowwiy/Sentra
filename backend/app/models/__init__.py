from app.models.ai import AIInsight
from app.models.ai_local import AILocalModel, AILocalSettings, AIModelBenchmark
from app.models.alert import Alert, AlertRule, AlertSeverity, AlertStatus
from app.models.asset import Asset, AssetCriticality, AssetStatus, MonitoringMethod
from app.models.asset_context import (
    AssetBusinessContext,
    AssetContextChange,
    AssetEnvironment,
    AssetRole,
    AssetTag,
    ContextSource,
    DataSensitivity,
    NetworkZone,
)
from app.models.asset_lineage import AssetAgentLineage, LineageEndReason
from app.models.audit import AuditEvent
from app.models.case_operations import IncidentTask, NetworkControlRequest
from app.models.change import AssetChange, ChangeCategory, ChangeKind
from app.models.detection import (
    Detection,
    DetectionBaseline,
    DetectionConfidence,
    DetectionEvidence,
    DetectionSeverity,
    DetectionSignal,
    DetectionStatus,
)
from app.models.detection_rule import (
    CompileStatus,
    DetectionRuleMatch,
    DetectionRuleRecord,
    DetectionRuleStats,
    DetectionRuleVersion,
    RuleSource,
    RuleStatus,
)
from app.models.dhcp import AssetIdentityHistory, DhcpLease, DhcpSource
from app.models.discovery import (
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveryObservation,
    DiscoveryTrigger,
)
from app.models.endpoint import DetectionExclusion, EndpointActivity, ProcessInstance
from app.models.enrollment import AgentEnrollmentToken, EnrollmentTokenState
from app.models.event import EventLevel, SystemEvent
from app.models.exposure import AssetPort, PortStateValue
from app.models.forensics import (
    EvidencePackage,
    ForensicArtifact,
    Investigation,
    InvestigationNote,
)
from app.models.incident import (
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentAsset,
    IncidentDetection,
    IncidentFeedback,
    IncidentNote,
    IncidentThreatMatch,
    IncidentVulnerability,
)
from app.models.inventory import AssetInventory
from app.models.isolation import IsolationSession
from app.models.network import (
    NetworkDevice,
    NetworkDevicePoll,
    NetworkInterface,
    NetworkMacEntry,
    NetworkNeighbor,
    NetworkPollRecord,
    NetworkVlan,
    NetworkVlanMembership,
    SnmpCredentialProfile,
)
from app.models.process import AssetProcessSnapshot
from app.models.rate_limit import RateLimitHit
from app.models.report import Report, ReportArtifact
from app.models.response import (
    AgentCommand,
    Playbook,
    PlaybookRun,
    PlaybookVersion,
    ResponseExecution,
)
from app.models.risk import (
    AssetRisk,
    RiskConfidence,
    RiskContributionRecord,
    RiskLevel,
    RiskSnapshot,
)
from app.models.site import (
    Sensor,
    SensorEnrollmentToken,
    SensorJob,
    SensorJobBatch,
    SensorObservation,
    Site,
    SiteNetwork,
)
from app.models.telemetry import TelemetrySample
from app.models.threat_intel import (
    ThreatIndicator,
    ThreatIntelChange,
    ThreatIntelCursor,
    ThreatIntelMatch,
    ThreatIntelSource,
    ThreatIntelSync,
    VulnerabilityIntel,
)
from app.models.tool import ToolExecution
from app.models.topology import TopologyBuild, TopologyLink
from app.models.topology_history import NetworkChange, TopologySnapshot
from app.models.user import User, UserSession
from app.models.vulnerability import (
    AssetVulnerabilityState,
    Vulnerability,
    VulnerabilityAffected,
    VulnerabilityFinding,
    VulnerabilityFindingHistory,
    VulnerabilityProductMap,
    VulnerabilitySource,
    VulnerabilitySourceSync,
)
from app.models.wlan import (
    WlanAccessPoint,
    WlanAgentReport,
    WlanBss,
    WlanClient,
    WlanConfiguredNetwork,
    WlanObservation,
)

__all__ = [
    "AIInsight",
    "AILocalModel",
    "AILocalSettings",
    "AIModelBenchmark",
    "AgentCommand",
    "AgentEnrollmentToken",
    "Alert",
    "AlertRule",
    "AlertSeverity",
    "AlertStatus",
    "Asset",
    "AssetAgentLineage",
    "AssetBusinessContext",
    "AssetChange",
    "AssetContextChange",
    "AssetCriticality",
    "AssetEnvironment",
    "AssetIdentityHistory",
    "AssetInventory",
    "AssetPort",
    "AssetProcessSnapshot",
    "AssetRisk",
    "AssetRole",
    "AssetStatus",
    "AssetTag",
    "AssetVulnerabilityState",
    "AuditEvent",
    "ChangeCategory",
    "ChangeKind",
    "CompileStatus",
    "ContextSource",
    "DataSensitivity",
    "Detection",
    "DetectionBaseline",
    "DetectionConfidence",
    "DetectionEvidence",
    "DetectionExclusion",
    "DetectionRuleMatch",
    "DetectionRuleRecord",
    "DetectionRuleStats",
    "DetectionRuleVersion",
    "DetectionSeverity",
    "DetectionSignal",
    "DetectionStatus",
    "DhcpLease",
    "DhcpSource",
    "DiscoveryJob",
    "DiscoveryJobStatus",
    "DiscoveryObservation",
    "DiscoveryTrigger",
    "EndpointActivity",
    "EnrollmentTokenState",
    "EventLevel",
    "EvidencePackage",
    "ForensicArtifact",
    "Incident",
    "IncidentActivity",
    "IncidentAlert",
    "IncidentAsset",
    "IncidentDetection",
    "IncidentFeedback",
    "IncidentNote",
    "IncidentTask",
    "IncidentThreatMatch",
    "IncidentVulnerability",
    "Investigation",
    "InvestigationNote",
    "IsolationSession",
    "LineageEndReason",
    "MonitoringMethod",
    "NetworkChange",
    "NetworkControlRequest",
    "NetworkDevice",
    "NetworkDevicePoll",
    "NetworkInterface",
    "NetworkMacEntry",
    "NetworkNeighbor",
    "NetworkPollRecord",
    "NetworkVlan",
    "NetworkVlanMembership",
    "NetworkZone",
    "Playbook",
    "PlaybookRun",
    "PlaybookVersion",
    "PortStateValue",
    "ProcessInstance",
    "RateLimitHit",
    "Report",
    "ReportArtifact",
    "ResponseExecution",
    "RiskConfidence",
    "RiskContributionRecord",
    "RiskLevel",
    "RiskSnapshot",
    "RuleSource",
    "RuleStatus",
    "Sensor",
    "SensorEnrollmentToken",
    "SensorJob",
    "SensorJobBatch",
    "SensorObservation",
    "Site",
    "SiteNetwork",
    "SnmpCredentialProfile",
    "SystemEvent",
    "TelemetrySample",
    "ThreatIndicator",
    "ThreatIntelChange",
    "ThreatIntelCursor",
    "ThreatIntelMatch",
    "ThreatIntelSource",
    "ThreatIntelSync",
    "ToolExecution",
    "TopologyBuild",
    "TopologyLink",
    "TopologySnapshot",
    "User",
    "UserSession",
    "Vulnerability",
    "VulnerabilityAffected",
    "VulnerabilityFinding",
    "VulnerabilityFindingHistory",
    "VulnerabilityIntel",
    "VulnerabilityProductMap",
    "VulnerabilitySource",
    "VulnerabilitySourceSync",
    "WlanAccessPoint",
    "WlanAgentReport",
    "WlanBss",
    "WlanClient",
    "WlanConfiguredNetwork",
    "WlanObservation",
]

# Fase 6E.2: el historial de identidad se registra con un listener de sesión. Se instala al
# importar los modelos para que cualquier sesión (API, worker, CLI, tests) lo tenga.
from app.dhcp.history import install as _install_identity_history

_install_identity_history()
