import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "AI Network Threat Intelligence Platform"
    PROJECT_NAME: str = "AI Network Threat Intelligence Platform"
    ENVIRONMENT: str = "development"
    CORS_ORIGINS: list[str] = ["*"]
    
    # Database Settings
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "threat_intel"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/threat_intel"
    DATABASE_URL_DOCKER: str = "postgresql://postgres:postgres@db:5432/threat_intel"
    
    # Security & Auth
    SECRET_KEY: str = "dev_secret_key_change_in_production_9f8d7e6c5b4a3210"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    # Rate Limiting
    RATE_LIMIT_DEMO_PER_MINUTE: int = 10

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
