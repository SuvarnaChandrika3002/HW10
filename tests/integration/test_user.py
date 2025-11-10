import pytest
import logging
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models.user import User
from tests.conftest import create_fake_user, managed_db_session

logger = logging.getLogger(__name__)

def test_database_connection(db_session):
    result = db_session.execute(text("SELECT 1"))
    assert result.scalar() == 1
    logger.info("Database connection test passed")

def test_managed_session():
    with managed_db_session() as session:
        session.execute(text("SELECT 1"))
        try:
            session.execute(text("SELECT * FROM nonexistent_table"))
        except Exception as e:
            assert "nonexistent_table" in str(e)

def test_session_handling(db_session):
    initial_count = db_session.query(User).count()
    logger.info(f"Initial user count before test_session_handling: {initial_count}")
    assert initial_count == 0, f"Expected 0 users before test, found {initial_count}"
    user1 = User(
        first_name="Test",
        last_name="User",
        email="test1@example.com",
        username="testuser1",
        password="password123"
    )
    db_session.add(user1)
    db_session.commit()
    logger.info(f"Added user1: {user1.email}")
    current_count = db_session.query(User).count()
    logger.info(f"User count after adding user1: {current_count}")
    assert current_count == 1, f"Expected 1 user after adding user1, found {current_count}"
    try:
        user2 = User(
            first_name="Test",
            last_name="User",
            email="test1@example.com",
            username="testuser2",
            password="password456"
        )
        db_session.add(user2)
        db_session.commit()
    except IntegrityError:
        db_session.rollback()
        logger.info("IntegrityError caught and rolled back for user2.")
    found_user1 = db_session.query(User).filter_by(email="test1@example.com").first()
    assert found_user1 is not None, "User1 should still exist after rollback"
    assert found_user1.username == "testuser1"
    logger.info(f"Found user1 after rollback: {found_user1.email}")
    user3 = User(
        first_name="Test",
        last_name="User",
        email="test3@example.com",
        username="testuser3",
        password="password789"
    )
    db_session.add(user3)
    db_session.commit()
    logger.info(f"Added user3: {user3.email}")
    users = db_session.query(User).order_by(User.email).all()
    current_count = len(users)
    emails = {user.email for user in users}
    logger.info(f"Final user count: {current_count}, Emails: {emails}")
    assert current_count == 2, f"Should have exactly user1 and user3, found {current_count}"
    assert "test1@example.com" in emails
    assert "test3@example.com" in emails

def test_create_user_with_faker(db_session):
    user_data = create_fake_user()
    logger.info(f"Creating user with data: {user_data}")
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    assert user.id is not None
    assert user.email == user_data["email"]
    logger.info(f"Successfully created user with ID: {user.id}")

def test_create_multiple_users(db_session):
    users = []
    for _ in range(3):
        user_data = create_fake_user()
        user = User(**user_data)
        users.append(user)
        db_session.add(user)
    db_session.commit()
    assert len(users) == 3
    logger.info(f"Successfully created {len(users)} users")

def test_query_methods(db_session, seed_users):
    user_count = db_session.query(User).count()
    assert user_count >= len(seed_users)
    first_user = seed_users[0]
    found = db_session.query(User).filter_by(email=first_user.email).first()
    assert found is not None
    users_by_email = db_session.query(User).order_by(User.email).all()
    assert len(users_by_email) >= len(seed_users)

def test_transaction_rollback(db_session):
    initial_count = db_session.query(User).count()
    try:
        user_data = create_fake_user()
        user = User(**user_data)
        db_session.add(user)
        db_session.execute(text("SELECT * FROM nonexistent_table"))
        db_session.commit()
    except Exception:
        db_session.rollback()
    final_count = db_session.query(User).count()
    assert final_count == initial_count

def test_update_with_refresh(db_session, test_user):
    original_email = test_user.email
    original_update_time = test_user.updated_at
    new_email = f"new_{original_email}"
    test_user.email = new_email
    db_session.commit()
    db_session.refresh(test_user)
    assert test_user.email == new_email
    assert test_user.updated_at > original_update_time
    logger.info(f"Successfully updated user {test_user.id}")

@pytest.mark.slow
def test_bulk_operations(db_session):
    users_data = [create_fake_user() for _ in range(10)]
    users = [User(**data) for data in users_data]
    db_session.bulk_save_objects(users)
    db_session.commit()
    count = db_session.query(User).count()
    assert count >= 10
    logger.info(f"Successfully performed bulk operation with {len(users)} users")

def test_unique_email_constraint(db_session):
    first_user_data = create_fake_user()
    first_user = User(**first_user_data)
    db_session.add(first_user)
    db_session.commit()
    second_user_data = create_fake_user()
    second_user_data["email"] = first_user_data["email"]
    second_user = User(**second_user_data)
    db_session.add(second_user)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

def test_unique_username_constraint(db_session):
    first_user_data = create_fake_user()
    first_user = User(**first_user_data)
    db_session.add(first_user)
    db_session.commit()
    second_user_data = create_fake_user()
    second_user_data["username"] = first_user_data["username"]
    second_user = User(**second_user_data)
    db_session.add(second_user)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

def test_user_persistence_after_constraint(db_session):
    initial_user_data = {
        "first_name": "First",
        "last_name": "User",
        "email": "first@example.com",
        "username": "firstuser",
        "password": "password123"
    }
    initial_user = User(**initial_user_data)
    db_session.add(initial_user)
    db_session.commit()
    saved_id = initial_user.id
    try:
        duplicate_user = User(
            first_name="Second",
            last_name="User",
            email="first@example.com",
            username="seconduser",
            password="password456"
        )
        db_session.add(duplicate_user)
        db_session.commit()
        assert False
    except IntegrityError:
        db_session.rollback()
    found_user = db_session.query(User).filter_by(id=saved_id).first()
    assert found_user is not None
    assert found_user.id == saved_id
    assert found_user.email == "first@example.com"
    assert found_user.username == "firstuser"

def test_error_handling():
    with pytest.raises(Exception) as exc_info:
        with managed_db_session() as session:
            session.execute(text("INVALID SQL"))
    assert "INVALID SQL" in str(exc_info.value)
