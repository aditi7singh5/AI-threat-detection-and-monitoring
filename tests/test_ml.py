from app.models.schemas import LogEvent, CloudProvider
from app.core.ml_engine import ml_engine
from datetime import datetime, timezone

def test_ml_anomaly_scoring():
    normal_log = LogEvent(
        id="normal-1",
        timestamp=datetime.now(timezone.utc).isoformat(),
        provider=CloudProvider.AWS,
        source_service="S3",
        identity="arn:aws:iam::123:user/normal-dev",
        action="GetObject",
        resource="bucket/file.json",
        ip_address="54.210.1.1",
        geo_location="US-East",
        user_agent="aws-cli",
        bytes_transferred=1024
    )

    scored_log, alert = ml_engine.process_event(normal_log)
    assert scored_log.anomaly_score is not None
    assert 0.0 <= scored_log.anomaly_score <= 100.0
