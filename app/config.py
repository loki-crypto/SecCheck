"""
Security Checklist Application - Configuration
"""
from pydantic_settings import BaseSettings
from functools import lru_cache
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # App info
    APP_NAME: str = "Security Checklist"
    APP_VERSION: str = "1.0.0"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str = "change-this-in-production"
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
