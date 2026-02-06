"""
Security Checklist Application - Configuration
"""
from pydantic_settings import BaseSettings
from functools import lru_cache
import os
import secrets
import logging
import json
from datetime import datetime


# ============== JSON LOGGING ==============

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "ip_address"):
            log_data["ip_address"] = record.ip_address
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id
        if hasattr(record, "action"):
            log_data["action"] = record.action
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms
            
        return json.dumps(log_data, ensure_ascii=False)


def setup_logging(json_format: bool = True, level: str = "INFO"):
    """Configure application logging"""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
    
    root_logger.addHandler(console_handler)
    
    # File handler (always JSON for parsing)
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    file_handler = logging.FileHandler(
        f"{log_dir}/app.log",
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(file_handler)
    
    # Security events file
    security_handler = logging.FileHandler(
        f"{log_dir}/security.log",
        encoding="utf-8"
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(JSONFormatter())
    
    security_logger = logging.getLogger("security")
    security_logger.addHandler(security_handler)
    
    return root_logger


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # App info
    APP_NAME: str = "Security Checklist"
    APP_VERSION: str = "1.0.0"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Security - Gera uma chave segura se não definida
    SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # CORS
    CORS_ORIGINS: list = ["http://localhost:8000", "http://127.0.0.1:8000"]
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/security_checklist.db"
    
    # Upload
    MAX_UPLOAD_SIZE_MB: int = 10
    UPLOAD_DIR: str = "./uploads"
    UPLOAD_FOLDER: str = "./uploads"
    ALLOWED_EXTENSIONS: set = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".md", ".json", ".xml", ".csv"}
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Admin user
    ADMIN_USERNAME: str = "admin"
    ADMIN_EMAIL: str = "admin@example.com"
    ADMIN_PASSWORD: str = "admin123"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_JSON_FORMAT: bool = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Gera SECRET_KEY segura se não definida ou se é o valor padrão inseguro
        if not self.SECRET_KEY or self.SECRET_KEY in ["change-this-in-production", ""]:
            self.SECRET_KEY = self._generate_or_load_secret_key()
    
    def _generate_or_load_secret_key(self) -> str:
        """Generate or load a persistent secret key"""
        # Lista de locais possíveis para o arquivo de chave (em ordem de prioridade)
        # Usa /app/data que já é um volume persistente no Docker
        secret_locations = [
            "/app/data/.secret_key",      # Docker volume (melhor opção)
            "data/.secret_key",           # Local development
            ".secret_key",                # Fallback
        ]
        
        # Tenta carregar chave existente de qualquer localização
        for secret_file in secret_locations:
            if os.path.exists(secret_file):
                try:
                    with open(secret_file, "r") as f:
                        key = f.read().strip()
                        if len(key) >= 32:
                            return key
                except Exception:
                    continue
        
        # Gera nova chave segura
        new_key = secrets.token_urlsafe(64)
        
        # Salva para persistência - tenta cada localização
        saved = False
        for secret_file in secret_locations:
            try:
                secret_dir = os.path.dirname(secret_file)
                if secret_dir:
                    os.makedirs(secret_dir, exist_ok=True)
                with open(secret_file, "w") as f:
                    f.write(new_key)
                os.chmod(secret_file, 0o600)  # Apenas owner pode ler
                saved = True
                break
            except Exception:
                continue
        
        if not saved:
            logging.warning("Could not persist SECRET_KEY - it will be regenerated on restart")
        
        return new_key
    
    class Config:
        env_file = ".env"
        extra = "allow"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Global settings instance
settings = get_settings()


# Create directories if they don't exist
def ensure_directories():
    """Create required directories"""
    settings = get_settings()
    os.makedirs("data", exist_ok=True)
    os.makedirs(settings.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports_output", exist_ok=True)
