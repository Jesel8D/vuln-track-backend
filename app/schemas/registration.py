"""Public account input; internal identity and membership fields are forbidden."""

import re
import unicodedata

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(strict=True, min_length=3, max_length=80)
    password: SecretStr = Field(min_length=15, max_length=128)

    @field_validator("username", mode="before")
    @classmethod
    def normalize_username(cls, value):
        # Do not transliterate/confuse Unicode identifiers; login uses this same ASCII space.
        if not isinstance(value, str) or not value.isascii():
            raise ValueError("Usuario ASCII requerido")
        value = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,79}", value):
            raise ValueError("Usuario inválido")
        return value

    @model_validator(mode="after")
    def reject_trivial_password(self):
        password = self.password.get_secret_value()
        if any(unicodedata.category(char).startswith("C") for char in password):
            raise ValueError("La contraseña contiene caracteres no admitidos")
        simplified = re.sub(r"[^a-z0-9]", "", password.casefold())
        common = {
            "password",
            "password123",
            "password123456789",
            "123456789012345",
            "qwertyuiopasdfgh",
            "letmein",
            "admin",
            "administrator",
            "vulntrack",
            "contraseña",
            "contrasena",
            "correcthorsebatterystaple",
        }
        if (
            len(set(password)) < 5
            or simplified in common
            or simplified.rstrip("0123456789") in {
                "password", "vulntrack", "admin", "administrator", "contrasena", "letmein",
            }
            or simplified in {self.username, self.username + "123", self.username + "123456"}
            or any(
                password == password[:size] * (len(password) // size)
                for size in range(1, len(password) // 2 + 1)
                if len(password) % size == 0
            )
        ):
            raise ValueError("Elige una frase de contraseña menos predecible")
        return self
