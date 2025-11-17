# app/schemas/base.py
from pydantic import BaseModel, EmailStr, Field, ConfigDict, ValidationError, model_validator
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

# bcrypt has a hard 72-byte input limit
MAX_BCRYPT_BYTES = 72


class UserBase(BaseModel):
    """Base user schema with common fields"""
    first_name: str = Field(max_length=50, example="John")
    last_name: str = Field(max_length=50, example="Doe")
    email: EmailStr = Field(example="john.doe@example.com")
    username: str = Field(min_length=3, max_length=50, example="johndoe")

    model_config = ConfigDict(from_attributes=True)


class PasswordMixin(BaseModel):
    """Mixin for password validation (Pydantic schema)"""

    password: str = Field(min_length=6, max_length=128, example="SecurePass123")

    @model_validator(mode="before")
    @classmethod
    def validate_password(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure password meets complexity rules, and also truncate the password
        to bcrypt's 72-byte limit so downstream hashing never raises.
        """
        password = values.get("password")

        if not password:
            # Keep your original behavior for "missing password"
            raise ValidationError("Password is required", model=cls)

        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        if not any(char.isupper() for char in password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(char.islower() for char in password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one digit")

        # --- TRUNCATE to bcrypt's 72-byte limit (bytes, not characters) ---
        pw_bytes = password.encode("utf-8")
        if len(pw_bytes) > MAX_BCRYPT_BYTES:
            pw_bytes = pw_bytes[:MAX_BCRYPT_BYTES]
            # decode back to str safely (ignore partial multibyte characters)
            values["password"] = pw_bytes.decode("utf-8", errors="ignore")

        return values


class UserCreate(UserBase, PasswordMixin):
    """Schema for user creation"""
    pass


class UserLogin(PasswordMixin):
    """Schema for user login"""
    username: str = Field(
        description="Username or email",
        min_length=3,
        max_length=50,
        example="johndoe123",
    )
