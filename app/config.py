"""
app/config.py
Application settings loaded from environment variables / .env file.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Azure OpenAI
    AZURE_OPENAI_ENDPOINT: str = ""
    AZURE_OPENAI_API_KEY: str = ""
    AZURE_OPENAI_DEPLOYMENT: str = "gpt-4o"
    AZURE_OPENAI_API_VERSION: str = "2024-02-15-preview"

    # App
    APP_ENV: str = "development"
    MAX_IMAGE_SIZE_MB: int = 10
    MAX_TOKENS_RESPONSE: int = 4096
    REQUEST_TIMEOUT_SECONDS: int = 120

    @property
    def max_image_bytes(self) -> int:
        return self.MAX_IMAGE_SIZE_MB * 1024 * 1024

    @property
    def azure_configured(self) -> bool:
        return bool(self.AZURE_OPENAI_ENDPOINT and self.AZURE_OPENAI_API_KEY)


settings = Settings()
