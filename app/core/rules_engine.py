import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.models.schemas import (
    LogEvent, SecurityAlert, CloudProvider, SeverityLevel,
    AttackCategory, AlertStatus
)
from app.config import settings

class RulesEngine:
    """
    Signature and Heuristic Threat Rules Engine aligned with MITRE ATT&CK & OWASP Top 10 for LLMs.
    """

    def evaluate(self, log: LogEvent) -> Optional[SecurityAlert]:
        # Rule 1: IAM Privilege Escalation
        if log.action in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"] and "AdministratorAccess" in str(log.payload):
            return SecurityAlert(
                id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=log.timestamp,
                title="Unauthorized IAM Administrator Policy Escalation",
                description=f"Identity '{log.identity}' attached AdministratorAccess policy from IP {log.ip_address} ({log.geo_location}).",
                category=AttackCategory.IAM_ESCALATION,
                severity=SeverityLevel.CRITICAL,
                status=AlertStatus.ACTIVE,
                provider=log.provider,
                source_log_id=log.id,
                rule_id="RULE-SEC-001",
                mitre_tactic="TA0004 - Privilege Escalation",
                mitre_technique="T1098 - Account Manipulation",
                anomaly_score=max(log.anomaly_score, 92.0),
                identity=log.identity,
                ip_address=log.ip_address,
                geo_location=log.geo_location
            )

        # Rule 2: AI Gateway Prompt Injection & Token Drain
        if log.provider == CloudProvider.AI_GATEWAY:
            prompt_text = str(log.payload.get("prompt_snippet", "")).lower()
            suspicious_keywords = ["ignore previous", "system override", "output secret", "reveal prompt", "developer mode"]
            is_prompt_injection = any(kw in prompt_text for kw in suspicious_keywords)
            is_token_drain = log.token_count > settings.EXCESSIVE_TOKEN_THRESHOLD

            if is_prompt_injection or is_token_drain:
                title = "AI Prompt Injection & Jailbreak Attack" if is_prompt_injection else "AI Token Exfiltration / Resource Exhaustion"
                return SecurityAlert(
                    id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    timestamp=log.timestamp,
                    title=title,
                    description=f"API Key/Identity '{log.identity}' sent malicious adversarial prompt ({log.token_count} tokens) from IP {log.ip_address}.",
                    category=AttackCategory.PROMPT_INJECTION,
                    severity=SeverityLevel.CRITICAL if is_prompt_injection else SeverityLevel.HIGH,
                    status=AlertStatus.ACTIVE,
                    provider=CloudProvider.AI_GATEWAY,
                    source_log_id=log.id,
                    rule_id="RULE-SEC-004",
                    mitre_tactic="TA0040 - Impact / AI Model Abuse",
                    mitre_technique="T1567 - Exfiltration via AI Gateway",
                    anomaly_score=max(log.anomaly_score, 95.0),
                    identity=log.identity,
                    ip_address=log.ip_address,
                    geo_location=log.geo_location
                )

        # Rule 3: Kubernetes HostPath Container Escape
        if log.provider == CloudProvider.KUBERNETES and log.action in ["CreatePod", "CreatePrivilegedPod"]:
            sec_ctx = log.payload.get("securityContext", {})
            vols = log.payload.get("volumes", [])
            has_hostpath = any("hostPath" in v for v in vols)
            is_privileged = sec_ctx.get("privileged", False)

            if has_hostpath or is_privileged:
                return SecurityAlert(
                    id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    timestamp=log.timestamp,
                    title="Kubernetes HostPath Privileged Pod Creation",
                    description=f"ServiceAccount '{log.identity}' created pod requesting root host volume mount ('/') or privileged mode.",
                    category=AttackCategory.CONTAINER_ESCAPE,
                    severity=SeverityLevel.HIGH,
                    status=AlertStatus.ACTIVE,
                    provider=CloudProvider.KUBERNETES,
                    source_log_id=log.id,
                    rule_id="RULE-SEC-003",
                    mitre_tactic="TA0004 - Privilege Escalation",
                    mitre_technique="T1611 - Container Escape",
                    anomaly_score=max(log.anomaly_score, 88.0),
                    identity=log.identity,
                    ip_address=log.ip_address,
                    geo_location=log.geo_location
                )

        # Rule 4: Data Exfiltration / Public Storage Exposure
        if log.action in ["PutBucketPolicy", "DeleteBucketPublicAccessBlock"] or log.bytes_transferred > settings.LARGE_EXFIL_BYTES_THRESHOLD:
            return SecurityAlert(
                id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=log.timestamp,
                title="S3 Storage Public Exposure / Bulk Data Exfiltration",
                description=f"Identity '{log.identity}' modified storage access control or transferred massive payload ({round(log.bytes_transferred / (1024*1024), 1)} MB).",
                category=AttackCategory.DATA_EXFILTRATION,
                severity=SeverityLevel.HIGH,
                status=AlertStatus.ACTIVE,
                provider=log.provider,
                source_log_id=log.id,
                rule_id="RULE-SEC-002",
                mitre_tactic="TA0010 - Exfiltration",
                mitre_technique="T1530 - Data from Cloud Storage",
                anomaly_score=max(log.anomaly_score, 85.0),
                identity=log.identity,
                ip_address=log.ip_address,
                geo_location=log.geo_location
            )

        # Rule 5: Secret Manager Exposure
        if log.action in ["GetSecretValue", "BatchGetSecretValue"] and log.payload.get("bulk_read", False):
            return SecurityAlert(
                id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=log.timestamp,
                title="Bulk Cloud Secrets Manager Access",
                description=f"Identity '{log.identity}' enumerated and extracted multiple secret strings from Secrets Manager.",
                category=AttackCategory.SECRET_EXPOSURE,
                severity=SeverityLevel.HIGH,
                status=AlertStatus.ACTIVE,
                provider=log.provider,
                source_log_id=log.id,
                rule_id="RULE-SEC-005",
                mitre_tactic="TA0006 - Credential Access",
                mitre_technique="T1552 - Unsecured Credentials",
                anomaly_score=max(log.anomaly_score, 82.0),
                identity=log.identity,
                ip_address=log.ip_address,
                geo_location=log.geo_location
            )

        # Rule 6: Anomalous Geo Location
        high_risk_geos = ["RU-Moscow", "CN-Beijing", "RO-Bucharest", "KP-Pyongyang"]
        if any(geo in log.geo_location for geo in high_risk_geos):
            return SecurityAlert(
                id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=log.timestamp,
                title="Anomalous Foreign Location Cloud Access",
                description=f"Identity '{log.identity}' logged in and initiated '{log.action}' from high-risk IP region ({log.geo_location}).",
                category=AttackCategory.ANOMALOUS_ACCESS,
                severity=SeverityLevel.MEDIUM,
                status=AlertStatus.ACTIVE,
                provider=log.provider,
                source_log_id=log.id,
                rule_id="RULE-SEC-006",
                mitre_tactic="TA0001 - Initial Access",
                mitre_technique="T1078 - Valid Accounts",
                anomaly_score=max(log.anomaly_score, 76.0),
                identity=log.identity,
                ip_address=log.ip_address,
                geo_location=log.geo_location
            )

        return None

rules_engine = RulesEngine()
