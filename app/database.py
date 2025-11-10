from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError
from .config import settings

def get_engine(database_url: str = settings.DATABASE_URL):
    try:
        engine = create_engine(database_url, echo=True)
        return engine
    except SQLAlchemyError as e:
        print(f"Error creating engine: {e}")
        raise

def get_sessionmaker(engine):
    return sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )

engine = get_engine()
SessionLocal = get_sessionmaker(engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
