from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )

    ollama_model: str = "llama3:8b"
    
    # Database
    database_url: str = "sqlite:///./phishdetect.db"

    # Logging
    log_level: str = "INFO"

    # API Settings
    api_title: str = "Phishing-Detector AI API"
    api_version: str = "1.0.0"
    api_description: str = "AI-powered phishing and deepfake detection"


# Global settings instance
settings = Settings()