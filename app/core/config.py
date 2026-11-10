import ipaddress
import re
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


def validate_origin(origin: str) -> str:
    """Accept only canonical HTTP origins, never URL patterns, paths or credentials."""
    try:
        parsed = urlsplit(origin)
        host, port = parsed.hostname, parsed.port
        if (
            not origin.isascii()
            or origin != origin.strip()
            or "*" in origin
            or any(ord(char) <= 32 for char in origin)
            or parsed.scheme not in {"http", "https"}
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or "%" in host
            or port is not None
            and not 1 <= port <= 65535
        ):
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if (
                len(host) > 253
                or any(
                    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels
                )
                or re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", labels[-1])
            ):
                raise ValueError from None
            authority = host
        else:
            authority = f"[{address.compressed}]" if address.version == 6 else str(address)
        if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
            authority += f":{port}"
        if origin != f"{parsed.scheme}://{authority}":
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError(
            "CORS requiere orígenes canónicos HTTP(S), sin rutas ni comodines"
        ) from None
    return origin


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    environment: Literal["development", "production", "test"] = "development"
    database_url: SecretStr
    token_secret: SecretStr
    cors_origins: list[str] = Field(default_factory=list, max_length=20)
    cors_allow_credentials: bool = False
    cors_max_age: int = Field(default=600, ge=0, le=3600)
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
    cve_worker_enabled: bool = True
    nvd_api_key: SecretStr | None = Field(default=None, repr=False)
    nvd_timeout_seconds: int = Field(default=10, ge=1, le=20)
    login_attempts_per_minute: int = Field(default=10, ge=1, le=100)
    workspace_hmac_key: SecretStr | None = Field(default=None, repr=False)

    @field_validator("cors_origins")
    @classmethod
    def explicit_origins(cls, origins):
        if len(origins) != len(set(origins)):
            raise ValueError("CORS_ORIGINS no admite duplicados")
        return [validate_origin(origin) for origin in origins]

    @field_validator("workspace_hmac_key", mode="before")
    @classmethod
    def valid_workspace_hmac_key(cls, value):
        if value == "":
            return None
        if value is not None:
            secret = value.get_secret_value() if isinstance(value, SecretStr) else value
            if len(secret) != 64 or any(char not in "0123456789abcdef" for char in secret):
                raise ValueError("WORKSPACE_HMAC_KEY requiere 32 bytes en hexadecimal minúsculo")
        return value

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
        if self.cors_allow_credentials:
            raise ValueError("CORS con cookies/credenciales implícitas no habilitado; usar Bearer")
        if self.environment == "production":
            for origin in self.cors_origins:
                parsed = urlsplit(origin)
                host = parsed.hostname
                try:
                    address = ipaddress.ip_address(host)
                    loopback = address.is_loopback or (
                        address.version == 6
                        and address.ipv4_mapped is not None
                        and address.ipv4_mapped.is_loopback
                    )
                except ValueError:
                    loopback = host == "localhost" or host.endswith(".localhost")
                if parsed.scheme != "https" or loopback:
                    raise ValueError("CORS producción requiere HTTPS y excluye localhost/loopback")
            if url.query.get("sslmode") != "verify-full" or not url.query.get("sslrootcert"):
                raise ValueError("Producción requiere sslmode=verify-full y sslrootcert")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
