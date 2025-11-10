import subprocess
import time
import logging
from typing import Generator, Dict, List
from contextlib import contextmanager

import pytest
import requests
from faker import Faker
from playwright.sync_api import sync_playwright, Browser, Page
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from app.database import Base, get_engine, get_sessionmaker
from app.models.user import User
from app.config import settings
from app.database_init import init_db, drop_db

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

fake = Faker()
Faker.seed(12345)

logger.info(f"Using database URL: {settings.DATABASE_URL}")

test_engine = get_engine(database_url=settings.DATABASE_URL)
TestingSessionLocal = get_sessionmaker(engine=test_engine)


def create_fake_user() -> Dict[str, str]:
    return {
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "email": fake.unique.email(),
        "username": fake.unique.user_name(),
        "password": fake.password(length=12)
    }


@contextmanager
def managed_db_session():
    session = TestingSessionLocal()
    try:
        yield session
    except SQLAlchemyError as e:
        logger.error(f"Database error: {str(e)}")
        session.rollback()
        raise
    finally:
        session.close()


def wait_for_server(url: str, timeout: int = 30) -> bool:
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    return False


class ServerStartupError(Exception):
    pass


@pytest.fixture(scope="session", autouse=True)
def setup_test_database(request):
    logger.info("Setting up test database...")
    Base.metadata.drop_all(bind=test_engine)
    logger.info("Dropped all existing tables.")
    Base.metadata.create_all(bind=test_engine)
    logger.info("Created all tables based on models.")
    init_db()
    logger.info("Initialized the test database with initial data.")
    yield
    preserve_db = request.config.getoption("--preserve-db")
    if preserve_db:
        logger.info("Skipping drop_db due to --preserve-db flag.")
    else:
        logger.info("Cleaning up test database...")
        drop_db()
        logger.info("Dropped test database tables.")


@pytest.fixture
def db_session(request) -> Generator[Session, None, None]:
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        logger.info("db_session teardown: about to truncate tables.")
        preserve_db = request.config.getoption("--preserve-db")
        if preserve_db:
            logger.info("Skipping table truncation due to --preserve-db flag.")
        else:
            logger.info("Truncating all tables now.")
            for table in reversed(Base.metadata.sorted_tables):
                logger.info(f"Truncating table: {table}")
                session.execute(table.delete())
            session.commit()
        session.close()
        logger.info("db_session teardown: done.")


@pytest.fixture
def fake_user_data() -> Dict[str, str]:
    return create_fake_user()


@pytest.fixture
def test_user(db_session: Session) -> User:
    user_data = create_fake_user()
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    logger.info(f"Created test user with ID: {user.id}")
    return user


@pytest.fixture
def seed_users(db_session: Session, request) -> List[User]:
    try:
        num_users = request.param
    except AttributeError:
        num_users = 5
    users = []
    for _ in range(num_users):
        user_data = create_fake_user()
        user = User(**user_data)
        users.append(user)
        db_session.add(user)
    db_session.commit()
    logger.info(f"Seeded {len(users)} users into the test database.")
    return users


@pytest.fixture(scope="session")
def fastapi_server():
    server_url = 'http://127.0.0.1:8000/'
    logger.info("Starting test server...")
    try:
        process = subprocess.Popen(
            ['python', 'main.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if not wait_for_server(server_url, timeout=30):
            raise ServerStartupError("Failed to start test server")
        logger.info("Test server started successfully.")
        yield
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        raise
    finally:
        logger.info("Terminating test server...")
        process.terminate()
        try:
            process.wait(timeout=5)
            logger.info("Test server terminated gracefully.")
        except subprocess.TimeoutExpired:
            logger.warning("Test server did not terminate in time; killing it.")
            process.kill()


@pytest.fixture(scope="session")
def browser_context():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )
        logger.info("Playwright browser launched.")
        try:
            yield browser
        finally:
            logger.info("Closing Playwright browser.")
            browser.close()


@pytest.fixture
def page(browser_context: Browser):
    context = browser_context.new_context(
        viewport={'width': 1920, 'height': 1080},
        ignore_https_errors=True
    )
    page = context.new_page()
    logger.info("Created new browser page.")
    try:
        yield page
    finally:
        logger.info("Closing browser page and context.")
        page.close()
        context.close()


def pytest_addoption(parser):
    parser.addoption(
        "--preserve-db",
        action="store_true",
        default=False,
        help="Keep test database after tests, and skip table truncation."
    )
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run tests marked as slow"
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="use --run-slow to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
