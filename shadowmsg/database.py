import sqlite3
from hashlib import sha256
from typing import Optional, List
from dataclasses import dataclass
import time
import logging
import os

from shadowmsg import APP_DIR
from shadowmsg.encryption import EncryptionHandler


@dataclass
class User:
    username: str
    password: str
    destination_ip: str


@dataclass
class DatabaseManager:
    db_path: str = os.path.join(APP_DIR, "user_data.db")
    retries: int = 5
    delay: float = 0.5

    def __post_init__(self):
        logging.info(f"Database path: {self.db_path}")
        self.setup_database()

    def setup_database(self):
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        destination_ip TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        key BLOB NOT NULL,
                        FOREIGN KEY (username) REFERENCES users (username)
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS contacts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        contact_username TEXT NOT NULL,
                        contact_ip TEXT NOT NULL
                    )
                """)
                conn.commit()
        except sqlite3.OperationalError as e:
            logging.error(f"Error setting up database: {e}")
            raise

    def _get_connection(self):
        try:
            return sqlite3.connect(self.db_path)
        except sqlite3.OperationalError as e:
            logging.error(f"Error opening database connection: {e}")
            raise

    def _execute_with_retry(self, query: str, params: tuple):
        for _ in range(self.retries):
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(query, params)
                    conn.commit()
                    return cursor
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e):
                    time.sleep(self.delay)
                else:
                    raise
        raise sqlite3.OperationalError("Database is locked after multiple attempts")

    @staticmethod
    def hash_password(password: str) -> str:
        return sha256(password.encode()).hexdigest()

    def insert_user(self, user: User, encryption_handler: EncryptionHandler):
        hashed_password = self.hash_password(user.password)
        encrypted_ip = encryption_handler.encrypt(user.destination_ip).hex()
        self._execute_with_retry(
            "INSERT INTO users (username, password, destination_ip) VALUES (?, ?, ?)",
            (user.username, hashed_password, encrypted_ip),
        )

    def store_key(self, username: str, key: bytes):
        self._execute_with_retry(
            "INSERT INTO keys (username, key) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET key=excluded.key",
            (username, key),
        )

    def get_key(self, username: str) -> Optional[bytes]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM keys WHERE username = ?", (username,))
            key = cursor.fetchone()
            if key:
                return key[0]
        return None

    def get_user(self, username: str) -> Optional[User]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, password, destination_ip FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                return User(username=user[0], password=user[1], destination_ip=user[2])
        return None

    def verify_user(self, username: str, password: str) -> bool:
        user = self.get_user(username)
        if user:
            hashed_password = user.password
            return hashed_password == self.hash_password(password)
        return False

    def get_user_ips(self, username: str, encryption_handler: EncryptionHandler) -> List[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT destination_ip FROM users WHERE username = ?", (username,))
            rows = cursor.fetchall()
            ips = []
            for row in rows:
                encrypted_ip = bytes.fromhex(row[0])
                decrypted_ip = encryption_handler.decrypt(encrypted_ip)
                ips.append(decrypted_ip)
            return ips

    def add_ip_for_user(self, username: str, ip: str, encryption_handler: EncryptionHandler):
        encrypted_ip = encryption_handler.encrypt(ip).hex()
        self._execute_with_retry(
            "INSERT INTO users (username, password, destination_ip) VALUES (?, ?, ?) ON CONFLICT(username) DO UPDATE SET destination_ip=excluded.destination_ip",
            (username, "", encrypted_ip)
        )

    def insert_contact(self, username: str, contact_username: str, contact_ip: str):
        self._execute_with_retry(
            "INSERT INTO contacts (username, contact_username, contact_ip) VALUES (?, ?, ?)",
            (username, contact_username, contact_ip)
        )

    def get_contacts(self, username: str) -> List[tuple[str, str]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT contact_username, contact_ip FROM contacts WHERE username = ?", (username,))
            contacts = cursor.fetchall()
            return [(contact[0], contact[1]) for contact in contacts]
