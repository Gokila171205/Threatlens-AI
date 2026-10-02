from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional
from pathlib import Path
import os

_backend_dir = Path(__file__).resolve().parent.parent.parent
_env_files = [
    str(_backend_dir / ".env"),
    "backend/.env",
    ".env",
]

class Settings(BaseSettings):
    app_name: str = "ThreatLens AI"
    host: str = "0.0.0.0"
    port: int = 8000
    allowed_origins: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://localhost:8000"
    jwt_secret: str = "threatlens-secret-key"
    max_upload_size_mb: int = 50
    upload_directory: str = "storage/uploads"
    threat_model_path: str = "app/ml/models/malware_classifier_ember_grouped.joblib"
    fallback_model_path: str = "app/ml/models/malware_classifier.joblib"
    active_metadata_path: str = "app/ml/models/model_metadata_active.json"
    
    # MongoDB Atlas persistence configuration
    mongo_uri: Optional[str] = None
    mongo_db_name: str = "Threatlens"
    
    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]
        
    model_config = SettingsConfigDict(
        env_file=_env_files,
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
