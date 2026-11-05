"""Request and response models."""

import unicodedata
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,30}[A-Za-z0-9])$"


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=10, max_length=128)
    # Accepted only so the route can reject it explicitly with 403. It is never
    # read when creating the account.
    role: Any = None

    @field_validator("username", mode="before")
    @classmethod
    def _normalise_username(cls, value: Any) -> Any:
        if isinstance(value, str):
            return unicodedata.normalize("NFKC", value).strip()
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("username", mode="before")
    @classmethod
    def _normalise_username(cls, value: Any) -> Any:
        if isinstance(value, str):
            return unicodedata.normalize("NFKC", value).strip()
        return value


class RecordCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=16_384)

    @field_validator("title", mode="before")
    @classmethod
    def _strip_title(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("title", "body")
    @classmethod
    def _reject_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("must not contain NUL characters")
        return value

    @field_validator("body")
    @classmethod
    def _reject_blank_body(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value


class UserOut(BaseModel):
    id: int
    username: str
    role: str


class LoginOut(BaseModel):
    token: str
    token_type: str = "Bearer"
    expires_at: str
    expires_in: int


class RecordOut(BaseModel):
    id: int
    title: str
    body: str
    created_at: str
