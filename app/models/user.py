# app/models/user.py
from datetime import datetime, timedelta, timezone
import uuid
from typing import Optional, Dict, Any
from sqlalchemy import or_
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import declarative_base
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import ValidationError

from app.schemas.base import UserCreate
from app.schemas.user import UserResponse, Token

# --- ensure direct bcrypt calls also truncate to 72 bytes ---
import bcrypt as _bcrypt_lib

_original_bcrypt_hashpw = _bcrypt_lib.hashpw
_original_bcrypt_checkpw = _bcrypt_lib.checkpw


def _safe_bcrypt_hashpw(password_bytes, salt):
    # password_bytes expected as bytes; truncate to 72 bytes
    if not isinstance(password_bytes, (bytes, bytearray)):
        password_bytes = str(password_bytes).encode("utf-8")
    safe = password_bytes[:72]
    return _original_bcrypt_hashpw(safe, salt)


def _safe_bcrypt_checkpw(password_bytes, hashed):
    if not isinstance(password_bytes, (bytes, bytearray)):
        password_bytes = str(password_bytes).encode("utf-8")
    safe = password_bytes[:72]
    return _original_bcrypt_checkpw(safe, hashed)


# apply the monkeypatch
_bcrypt_lib.hashpw = _safe_bcrypt_hashpw
_bcrypt_lib.checkpw = _safe_bcrypt_checkpw
# --- end bcrypt direct wrapper ---


Base = declarative_base()

# -------------------------
# safe passlib bcrypt setup
# -------------------------
MAX_BCRYPT_BYTES = 72

# create the passlib context first
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# keep originals
_original_pwd_hash = pwd_context.hash
_original_pwd_verify = pwd_context.verify


def _truncate_to_72_str(secret) -> str:
    """
    Ensure we return a str truncated to 72 bytes (utf-8) so passlib/bcrypt never sees >72 bytes.
    """
    if isinstance(secret, bytes):
        b = secret[:MAX_BCRYPT_BYTES]
    else:
        b = str(secret).encode("utf-8")
        if len(b) > MAX_BCRYPT_BYTES:
            b = b[:MAX_BCRYPT_BYTES]
    # decode ignoring any partial multibyte sequences
    return b.decode("utf-8", errors="ignore")


def _safe_pwd_hash(secret, *args, **kwargs):
    safe = _truncate_to_72_str(secret)
    return _original_pwd_hash(safe, *args, **kwargs)


def _safe_pwd_verify(secret, stored_hash, *args, **kwargs):
    safe = _truncate_to_72_str(secret)
    return _original_pwd_verify(safe, stored_hash, *args, **kwargs)


# replace the context methods with safe wrappers (module-level)
pwd_context.hash = _safe_pwd_hash
pwd_context.verify = _safe_pwd_verify
# -------------------------
# end safe passlib setup
# -------------------------

# Move to config in future
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class User(Base):
    __tablename__ = 'users'

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False)  # stores bcrypt hash as str
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User(name={self.first_name} {self.last_name}, email={self.email})>"

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password safely: truncate to bcrypt limit and then hash via passlib.
        Returns the hash string.
        """
        safe_pw = _truncate_to_72_str(password)
        return pwd_context.hash(safe_pw)

    def verify_password(self, plain_password: str) -> bool:
        """
        Verify a plain password against the stored hash.
        Truncates the trial password the same way as hashing.
        """
        if not self.password:
            return False
        safe_pw = _truncate_to_72_str(plain_password)
        try:
            return pwd_context.verify(safe_pw, self.password)
        except Exception:
            return False

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> Optional[uuid.UUID]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
            return uuid.UUID(user_id) if user_id else None
        except (JWTError, ValueError, TypeError):
            return None

    @classmethod
    def register(cls, db, user_data: Dict[str, Any]) -> "User":
        """Register a new user with validation."""
        try:
            password = user_data.get('password', '')
            if len(password) < 6:
                raise ValueError("Password must be at least 6 characters long")

            existing_user = db.query(cls).filter(
                (cls.email == user_data.get('email')) |
                (cls.username == user_data.get('username'))
            ).first()

            if existing_user:
                raise ValueError("Username or email already exists")

            # Validate input via Pydantic schema (this will also apply schema truncation)
            user_create = UserCreate.model_validate(user_data)

            new_user = cls(
                first_name=user_create.first_name,
                last_name=user_create.last_name,
                email=user_create.email,
                username=user_create.username,
                password=cls.hash_password(user_create.password),
                is_active=True,
                is_verified=False
            )

            db.add(new_user)
            db.flush()
            return new_user

        except ValidationError as e:
            # pydantic ValidationError -> expose as ValueError to calling code/tests
            raise ValueError(str(e))
        except ValueError:
            # re-raise ValueError as-is
            raise

    @classmethod
    def authenticate(cls, db, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user and return token with user data.

        This will:
          - look up the user by username OR email
          - verify the password
          - update user.last_login (persisting the value so tests / callers can refresh)
          - return a dict payload containing token + user info (Token model dump)
        """
        user = db.query(cls).filter(
            (cls.username == username) | (cls.email == username)
        ).first()

        if not user or not user.verify_password(password):
            return None

        # Update last_login ensuring the new timestamp is strictly greater than previous
        prev = user.last_login
        now = datetime.utcnow()
        if prev is None:
            new_ts = now
        else:
            # ensure monotonic increase (tiny delta), use now if it's greater than prev + 1 microsecond
            candidate = prev + timedelta(microseconds=1)
            new_ts = now if now > candidate else candidate

        # assign and persist
        user.last_login = new_ts
        db.add(user)
        # commit here so callers/tests that refresh the instance will see the change
        db.commit()
        # refresh to ensure SQLAlchemy instance is up-to-date
        try:
            db.refresh(user)
        except Exception:
            # ignore refresh failure in case the session semantics differ
            pass

        user_response = UserResponse.model_validate(user)
        token_response = Token(
            access_token=cls.create_access_token({"sub": str(user.id)}),
            token_type="bearer",
            user=user_response
        )

        return token_response.model_dump()
