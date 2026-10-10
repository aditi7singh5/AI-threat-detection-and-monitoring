from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    KUBERNETES = "KUBERNETES"
    AI_GATEWAY = "AI_GATEWAY"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackCategory(str, Enum):
    IAM_ESCALATION = "IAM Escalation"
    DATA_EXFILTRATION = "Data Exfiltration"
    PROMPT_INJECTION = "AI Prompt Injection"
    RESOURCE_HIJACKING = "Resource Hijacking / Cryptojacking"
    ANOMALOUS_ACCESS = "Anomalous Geo / Access Pattern"
    CONTAINER_ESCAPE = "Container Escape / K8s Privilege"
    SECRET_EXPOSURE = "Secret Manager Exposure"


class AlertStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    DISMISSED = "DISMISSED"


class LogEvent(BaseModel):
    id: str
    timestamp: str
    provider: CloudProvider
    source_service: str  # e.g., "IAM", "S3", "K8s-Audit", "OpenAI-Gateway", "VPC-Flow"
    identity: str        # e.g., "arn:aws:iam::123456:user/dev", "system:serviceaccount"
    action: str          # e.g., "AttachUserPolicy", "GetSecretValue", "ChatCompletion"
    resource: str        # e.g., "arn:aws:s3:::customer-pii-data", "pod/cluster-admin"
    ip_address: str
    geo_location: str    # e.g., "US-East (Virginia)", "CN-Beijing", "RU-Moscow"
    user_agent: str
    bytes_transferred: int = 0
    token_count: int = 0
    payload: Dict[str, Any] = Field(default_factory=dict)
    anomaly_score: float = 0.0  # Range: 0.0 to 100.0


class SecurityAlert(BaseModel):
    id: str
    timestamp: str
    title: str
    description: str
    category: AttackCategory
    severity: SeverityLevel
    status: AlertStatus = AlertStatus.ACTIVE
    provider: CloudProvider
    source_log_id: str
    rule_id: str
    mitre_tactic: str      # e.g. "TA0004 - Privilege Escalation"
    mitre_technique: str   # e.g. "T1098 - Account Manipulation"
    anomaly_score: float
    identity: str
    ip_address: str
    geo_location: str
    ai_analysis: Optional[Dict[str, Any]] = None
    mitigation_playbook: Optional[List[str]] = None


class SystemMetrics(BaseModel):
    total_logs_processed: int
    active_threats_count: int
    critical_alerts_count: int
    high_alerts_count: int
    mitigated_count: int
    average_anomaly_index: float
    ai_gateway_health: str  # "HEALTHY", "WARNING", "UNDER_ATTACK"
    monitored_assets: int
    simulator_running: bool


class AttackInjectionRequest(BaseModel):
    scenario: str  # "iam_privilege_escalation", "data_exfiltration", "prompt_injection", "k8s_escape", "impossible_travel"
    target_provider: Optional[CloudProvider] = CloudProvider.AWS


class MitigationRequest(BaseModel):
    action_type: str  # "revoke_credentials", "quarantine_resource", "block_ip", "throttle_api_key"
    notes: Optional[str] = None
