import os

class Settings:
    PROJECT_NAME: str = "SentinelShield AI - Cloud & AI Threat Detection Engine"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Anomaly Detection Parameters
    ANOMALY_SCORE_THRESHOLD: float = 72.0  # Events with score > 72 trigger ML alert
    ML_CONTAMINATION: float = 0.05         # Expected proportion of anomalies (5%)
    
    # Threat Rules Sensitivity
    EXCESSIVE_TOKEN_THRESHOLD: int = 40000 # Single prompt token count
    LARGE_EXFIL_BYTES_THRESHOLD: int = 100 * 1024 * 1024 # 100 MB
    
    # Simulator Defaults
    DEFAULT_SIMULATOR_INTERVAL_SEC: float = 1.5
    
    # OpenAI / LLM Integration (Optional)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    AI_MODEL_NAME: str = os.getenv("AI_MODEL_NAME", "gpt-4o-mini")

settings = Settings()
