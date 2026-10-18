from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All secrets come from the environment (see .env.example); nothing is hard-coded."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_", extra="ignore")

    database_url: str = "sqlite:///./sentinel.db"
    # Base64 Ed25519 seed used to sign rule packs. Without it, publishing is disabled.
    rules_signing_seed: str = ""
    # One-time token that lets the first administrator register. Rotate/clear after use.
    admin_bootstrap_token: str = ""
    virustotal_api_key: str = ""
    google_webrisk_api_key: str = ""
    rate_limit_per_minute: int = 60
    register_limit_per_hour: int = 20
    max_body_bytes: int = 256 * 1024
    provider_timeout_seconds: float = 6.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
