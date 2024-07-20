import pytest
import sqlite3
import uuid
from shadowmessenger.master import DatabaseManager, IEncryptionHandler, User

@pytest.fixture(scope="module")
def db_manager():
    """
    Fixture to create a DatabaseManager instance with a test database.
    """
    db_manager = DatabaseManager(db_path="test_data.db")
    db_manager.setup_database()
    yield db_manager
    # Teardown
    conn = sqlite3.connect("test_data.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM keys")
    conn.commit()
    conn.close()

@pytest.fixture
def encryption_handler():
    """
    Fixture to create an EncryptionHandler instance with a test key.
    """
    class SimpleEncryptionHandler(IEncryptionHandler):
        def encrypt(self, data: str) -> bytes:
            return data.encode()

        def decrypt(self, data: bytes) -> str:
            return data.decode()
    
    return SimpleEncryptionHandler()

@pytest.fixture
def sample_user():
    """
    Fixture to create a sample User instance.
    """
    unique_username = f"testuser_{uuid.uuid4()}"
    return User(username=unique_username, password="87654321", destination_ip="69.42.0.69")

def test_setup_database(db_manager):
    """
    Test to verify the database setup.
    """
    conn = sqlite3.connect(db_manager.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = cursor.fetchone()
    conn.close()
    assert table_exists is not None

def test_insert_user(db_manager, encryption_handler, sample_user):
    """
    Test to verify inserting a user into the database.
    """
    db_manager.insert_user(sample_user, encryption_handler)
    conn = sqlite3.connect(db_manager.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password, destination_ip FROM users WHERE username = ?", (sample_user.username,))
    user = cursor.fetchone()
    conn.close()
    assert user is not None
    assert user[0] == sample_user.username
    assert user[1] == db_manager.hash_password(sample_user.password)
    assert user[2] == encryption_handler.encrypt(sample_user.destination_ip).hex()

def test_verify_user(db_manager, encryption_handler, sample_user):
    """
    Test to verify user authentication.
    """
    db_manager.insert_user(sample_user, encryption_handler)
    assert db_manager.verify_user(sample_user.username, sample_user.password) is True
    assert db_manager.verify_user(sample_user.username, "wrongpassword") is False

def test_get_user_ips(db_manager, encryption_handler, sample_user):
    """
    Test to verify retrieving user IPs.
    """
    db_manager.insert_user(sample_user, encryption_handler)
    user_ips = db_manager.get_user_ips(sample_user.username, encryption_handler)
    assert user_ips == [sample_user.destination_ip]

def test_store_key(db_manager, sample_user, encryption_handler):
    """
    Test to verify storing and retrieving keys.
    """
    db_manager.insert_user(sample_user, encryption_handler)
    key = b'some_random_key'
    db_manager.store_key(sample_user.username, key)
    retrieved_key = db_manager.get_key(sample_user.username)
    assert retrieved_key == key

if __name__ == "__main__":
    pytest.main()
