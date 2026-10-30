from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    environment: Literal["development", "production", "test"] = "development"
    database_url: SecretStr
    token_secret: SecretStr
    token_ttl_seconds: int = Field(default=900, ge=60, le=900)
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=5, ge=0, le=50)
    db_pool_timeout: int = Field(default=30, ge=1, le=60)
    db_pool_recycle: int = Field(default=1800, ge=60)
    db_pool_pre_ping: bool = True
    db_connect_timeout: int = Field(default=5, ge=1, le=30)
    db_statement_timeout_ms: int = Field(default=10000, ge=100, le=60000)
    db_lock_timeout_ms: int = Field(default=3000, ge=100, le=10000)
    max_body_bytes: int = Field(default=8192, ge=1024, le=65536)
    login_attempts_per_minute: int = Field(default=10, ge=1, le=100)

    @model_validator(mode="after")
    def secure_configuration(self):
        try:
            url = make_url(self.database_url.get_secret_value())
        except Exception:
            raise ValueError("DATABASE_URL inválida") from None
        if url.drivername != "postgresql+psycopg" or not url.database or not url.host:
            raise ValueError("Se requiere PostgreSQL con psycopg, host y base explícitos")
        if not url.username or url.username in {"postgres", "vulntrack_owner"}:
            raise ValueError("Usar un login dedicado sin privilegios administrativos")
        secret = self.token_secret.get_secret_value()
        if len(secret.encode()) < 32 or len(set(secret)) < 12:
            raise ValueError("TOKEN_SECRET requiere al menos 32 bytes aleatorios")
        if self.environment == "production":
            if url.query.get("sslmode") != "verify-full" or not url.query.get("sslrootcert"):
                raise ValueError("Producción requiere sslmode=verify-full y sslrootcert")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
