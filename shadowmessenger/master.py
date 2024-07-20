import socket
import threading
import os
import time
from Crypto.Cipher import AES
from Crypto.Util import number
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from dataclasses import dataclass
import sqlite3
from hashlib import sha256
from random import getrandbits
from typing import Optional

from shadowmessenger.interfaces import *

KEEP_ALIVE_INTERVAL = 10
TIMEOUT = 30

SHARED_KEY_PATH = "shared_key.key"


class EncryptionHandler(IEncryptionHandler):
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, message: str) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CFB)
        iv = cipher.iv
        encrypted_message = cipher.encrypt(message.encode("utf-8"))
        return iv + encrypted_message

    def decrypt(self, encrypted_message: bytes) -> str:
        try:
            iv = encrypted_message[:16]
            encrypted_message = encrypted_message[16:]
            cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
            decrypted_message = cipher.decrypt(encrypted_message).decode("utf-8")
            return decrypted_message
        except Exception as e:
            print(
                f"Decryption failed: {e} | Encrypted Message: {encrypted_message.hex()}"
            )
            return ""


@dataclass
class ProtocolMessage:
    message_type: str
    username: str
    content: str

    def to_bytes(self, encryption_handler: IEncryptionHandler) -> bytes:
        message = f"{self.message_type}:{self.username}:{self.content}"
        return encryption_handler.encrypt(message)

    @staticmethod
    def from_bytes(
        data: bytes, encryption_handler: IEncryptionHandler
    ) -> Optional["ProtocolMessage"]:
        decrypted_message = encryption_handler.decrypt(data)
        if not decrypted_message:
            return None
        try:
            message_type, username, content = decrypted_message.split(":", 2)
            return ProtocolMessage(message_type, username, content)
        except ValueError as e:
            print(
                f"Failed to parse message: {e} | Decrypted Message: {decrypted_message}"
            )
            return None

    @classmethod
    def hello_message(cls, username):
        return cls("HELLO", username, "###hello###")

    @classmethod
    def keep_alive_message(cls, username):
        return cls("KEEP_ALIVE", username, "###keepalive###")

    @classmethod
    def ack_message(cls, username):
        return cls("ACK", username, "###ack###")


class DiffieHellman(IDiffieHellman):
    def __init__(self, key_length: int = 2048, p: int = None, g: int = None):
        self.key_length = key_length
        self.private_key = getrandbits(self.key_length)
        self.p = p if p is not None else number.getPrime(self.key_length)
        self.g = g if g is not None else number.getPrime(self.key_length // 2)

    def get_params(self) -> tuple[int, int]:
        return self.p, self.g

    def generate_public_key(self) -> int:
        return pow(self.g, self.private_key, self.p)

    def generate_shared_secret(self, other_public_key: int) -> int:
        return pow(int(other_public_key), self.private_key, self.p)


class FileKeyStorage(IKeyStorage):
    def __init__(self, path: str):
        self.path = path

    def save_key(self, key: bytes):
        with open(self.path, "wb") as f:
            f.write(key)

    def load_key(self) -> Optional[bytes]:
        if os.path.exists(self.path):
            with open(self.path, "rb") as f:
                return f.read()
        return None


class MessageSender(IMessageSender):
    def send_keep_alive(
        self, sock: socket.socket, username: str, encryption_handler: IEncryptionHandler
    ):
        while True:
            time.sleep(KEEP_ALIVE_INTERVAL)
            try:
                sock.sendall(
                    ProtocolMessage.keep_alive_message(username).to_bytes(
                        encryption_handler
                    )
                )
            except Exception as e:
                print(f"Failed to send keep-alive message: {str(e)}")
                break

    def send_tcp_message(
        self, sock: socket.socket, username: str, encryption_handler: IEncryptionHandler
    ):
        try:
            sock.sendall(
                ProtocolMessage.hello_message(username).to_bytes(encryption_handler)
            )
            threading.Thread(
                target=self.send_keep_alive,
                args=(sock, username, encryption_handler),
                daemon=True,
            ).start()
            while True:
                message = input(
                    "Enter the message you want to send (or type 'exit' to close): "
                )
                if message.lower() == "exit":
                    break
                msg = ProtocolMessage("MESSAGE", username, message)
                sock.sendall(msg.to_bytes(encryption_handler))
                print("Message sent successfully!")
        except Exception as e:
            print(f"Failed to send message: {str(e)}")


class ConnectionHandler(IConnectionHandler):
    def handle_connection(
        self, conn: socket.socket, addr, encryption_handler: IEncryptionHandler
    ):
        print(f"\nConnection received from {addr[0]}:{addr[1]}")
        try:
            conn.settimeout(TIMEOUT)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received encrypted data: {data.hex()}")
                message = ProtocolMessage.from_bytes(data, encryption_handler)
                if message is None:
                    continue
                if message.message_type == "HELLO":
                    print(
                        f"\nRemote client {addr[0]}:{addr[1]} connected successfully."
                    )
                elif message.message_type == "KEEP_ALIVE":
                    conn.sendall(
                        ProtocolMessage.ack_message(message.username).to_bytes(
                            encryption_handler
                        )
                    )
                elif message.message_type == "ACK":
                    print(f"\nReceived acknowledgment from {addr[0]}:{addr[1]}")
                else:
                    print(
                        f"\nReceived message from {message.username}: {message.content}"
                    )
                    with open("received_messages.txt", "a") as f:
                        f.write(
                            f"{addr[0]}:{addr[1]} - {message.username}: {message.content}\n"
                        )
                    response = input("Enter your response: ")
                    if response.lower() == "exit":
                        break
                    response_msg = ProtocolMessage("MESSAGE", "Server", response)
                    conn.sendall(response_msg.to_bytes(encryption_handler))
        except socket.timeout:
            print(f"Connection with {addr[0]}:{addr[1]} timed out.")
        except Exception as e:
            print(f"Error during receiving message: {str(e)}")
        finally:
            conn.close()


class TcpListener(ITcpListener):
    def __init__(
        self,
        connection_handler: IConnectionHandler,
        key_exchange: IDiffieHellmanKeyExchange,
    ):
        self.connection_handler = connection_handler
        self.key_exchange = key_exchange

    def listen_tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 13377))
        sock.listen()
        print("Listening on port 13377...")
        while True:
            conn, addr = sock.accept()
            threading.Thread(
                target=self.key_exchange.perform_key_exchange,
                args=(conn, addr, self.connection_handler),
            ).start()


class IPResolver(IIPResolver):
    def resolve_ip(self, target_ip: str) -> str:
        if not isinstance(target_ip, str):
            raise TypeError("Input for resolve_ip was not a string value!")
        try:
            resolved_ip = socket.gethostbyname(target_ip)
            return resolved_ip
        except socket.gaierror:
            raise ValueError(f"Invalid IP address or hostname: {target_ip}")


class DatabaseManager:
    def __init__(self, db_path: str = "user_data.db"):
        self.db_path = db_path

    def setup_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                destination_ip TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    def hash_password(self, password: str) -> str:
        # Using hexdigest for consistent string format
        return sha256(password.encode()).hexdigest()

    def insert_user(
        self,
        username: str,
        password: str,
        destination_ip: str,
        encryption_handler: Optional['IEncryptionHandler'] = None,
    ):
        hashed_password = self.hash_password(password)
        encrypted_ip = (
            encryption_handler.encrypt(destination_ip).hex()
            if encryption_handler
            else destination_ip
        )
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, destination_ip) VALUES (?, ?, ?)",
            (username, hashed_password, encrypted_ip),
        )
        conn.commit()
        conn.close()

    def get_user(self, _username: str) -> Optional[tuple[str, str, str]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, password, destination_ip FROM users WHERE username = ?",
            (_username,),
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return None
        
        return user

    def verify_user(self, username: str, password: str) -> bool:
        user = self.get_user(username)
        if user:
            stored_hashed_password = user[1]
            input_hashed_password = self.hash_password(password)
            return stored_hashed_password == input_hashed_password
        return False

    def get_user_ips(
        self, username: str, encryption_handler: Optional['IEncryptionHandler']
    ) -> list[str]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT destination_ip FROM users WHERE username = ?", (username,)
        )
        rows = cursor.fetchall()
        conn.close()
        ips = []
        for row in rows:
            encrypted_ip = bytes.fromhex(row[0])
            decrypted_ip = encryption_handler.decrypt(encrypted_ip)
            ips.append(decrypted_ip)
        return ips


class UserInputHandler(IUserInputHandler):
    def __init__(
        self,
        database_manager: IDatabaseManager,
        ip_resolver: IIPResolver,
        key_storage: IKeyStorage,
    ):
        self.database_manager = database_manager
        self.ip_resolver = ip_resolver
        self.key_storage = key_storage

    def get_user_input(self) -> tuple[str, str]:
        while True:
            choice = input("\n1. Login\n2. Register\nEnter your choice: ")
            if choice == "1":
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                if self.database_manager.verify_user(username, password):
                    print(f"User {username} logged in successfully.")
                    encryption_handler = None
                    if os.path.exists(SHARED_KEY_PATH):
                        encryption_handler = EncryptionHandler(
                            self.key_storage.load_key()
                        )
                    try:
                        user_ips = self.database_manager.get_user_ips(
                            username, encryption_handler
                        )
                        if not user_ips:
                            raise ValueError("No IPs found for user.")
                        print("Select the destination IP address:")
                        for i, ip in enumerate(user_ips):
                            print(f"{i + 1}. {ip}")
                        selected_index = int(input("Enter your choice: ")) - 1
                        if selected_index < 0 or selected_index >= len(user_ips):
                            raise ValueError("Invalid choice.")
                        resolved_ip = self.ip_resolver.resolve_ip(
                            user_ips[selected_index]
                        )
                        return username, resolved_ip
                    except ValueError as e:
                        print(e)
                        continue
                else:
                    print("Invalid username or password. Please try again.")
            elif choice == "2":
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                target_ip = input("Enter the IP address of the target machine: ")
                try:
                    resolved_ip = self.ip_resolver.resolve_ip(target_ip)
                    print(f"User {username} created successfully.")
                    encryption_handler = None
                    if os.path.exists(SHARED_KEY_PATH):
                        encryption_handler = EncryptionHandler(
                            self.key_storage.load_key()
                        )
                    self.database_manager.insert_user(
                        username, password, resolved_ip, encryption_handler
                    )
                    return username, resolved_ip
                except ValueError as e:
                    print(e)
            else:
                print("Invalid choice. Please select 1 or 2.")


class DiffieHellmanKeyExchange(IDiffieHellmanKeyExchange):
    def __init__(self, key_storage: IKeyStorage, key_length: int = 2048):
        self.key_length = key_length
        self.key_storage = key_storage

    def perform_key_exchange(
        self, conn: socket.socket, addr, connection_handler: IConnectionHandler
    ):
        try:
            dh = DiffieHellman(key_length=self.key_length)  # AES key length
            public_key = dh.generate_public_key()
            print(f"Server public key: {public_key}")
            conn.sendall(str(public_key).encode("utf-8"))
            other_public_key = int(conn.recv(1024).decode("utf-8"))
            print(f"Client public key: {other_public_key}")
            shared_secret = dh.generate_shared_secret(other_public_key)
            print(f"Shared secret: {shared_secret}")

            # Generate and exchange key halves
            key_half = get_random_bytes(16)
            conn.sendall(key_half)
            other_key_half = conn.recv(16)

            print(f"Key halves (server): {key_half.hex()} and {other_key_half.hex()}")

            full_key = combine_key_halves(
                key_half, other_key_half, str(shared_secret).encode()
            )
            self.key_storage.save_key(full_key)

            encryption_handler = EncryptionHandler(full_key)
            connection_handler.handle_connection(conn, addr, encryption_handler)
        except Exception as e:
            print(f"Error during Diffie-Hellman key exchange: {str(e)}")
            conn.close()


class ClientConnection(IClientConnection):
    def __init__(
        self,
        key_storage: IKeyStorage,
        ip_resolver: IIPResolver,
        message_sender: IMessageSender,
        database_manager: IDatabaseManager
    ):
        self.key_storage = key_storage
        self.ip_resolver = ip_resolver
        self.message_sender = message_sender
        self.database_manager = database_manager

    def connect_and_communicate(self, username: str, target_ip: str):
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.ip_resolver.resolve_ip(target_ip), 13377))
                dh = DiffieHellman(key_length=2048)  # AES key length
                public_key = dh.generate_public_key()
                print(f"Client public key: {public_key}")
                sock.sendall(str(public_key).encode("utf-8"))
                other_public_key = int(sock.recv(1024).decode("utf-8"))
                print(f"Server public key: {other_public_key}")
                shared_secret = dh.generate_shared_secret(other_public_key)
                print(f"Shared secret: {shared_secret}")

                # Generate and exchange key halves
                key_half = get_random_bytes(16)
                sock.sendall(key_half)
                other_key_half = sock.recv(16)

                print(
                    f"Key halves (client): {key_half.hex()} and {other_key_half.hex()}"
                )

                full_key = combine_key_halves(
                    key_half, other_key_half, str(shared_secret).encode()
                )
                self.key_storage.save_key(full_key)

                encryption_handler = EncryptionHandler(full_key)
                threading.Thread(
                    target=self.message_sender.send_tcp_message,
                    args=(sock, username, encryption_handler),
                ).start()
                break
            except Exception as e:
                print(f"Failed to connect to {target_ip}: {e}")
                username, target_ip = UserInputHandler(
                    self.database_manager, self.ip_resolver, self.key_storage
                ).get_user_input()


def combine_key_halves(
    key_half1: bytes, key_half2: bytes, shared_secret: bytes
) -> bytes:
    combined = key_half1 + key_half2
    print(
        f"Combining key halves: {key_half1.hex()} + {key_half2.hex()} with shared secret: {shared_secret.hex()}"
    )
    return PBKDF2(combined + shared_secret, b"salt", dkLen=32, count=100000)


# Main Application Class
class Application:
    def __init__(
        self,
        database_manager: IDatabaseManager,
        tcp_listener: ITcpListener,
        client_connection: IClientConnection,
    ):
        self.database_manager = database_manager
        self.tcp_listener = tcp_listener
        self.client_connection = client_connection

    def run(self):
        self.database_manager.setup_database()
        threading.Thread(target=self.tcp_listener.listen_tcp, daemon=True).start()
        user_input_handler = UserInputHandler(
            self.database_manager, IPResolver(), FileKeyStorage(SHARED_KEY_PATH)
        )
        username, target_ip = user_input_handler.get_user_input()
        self.client_connection.connect_and_communicate(username, target_ip)


if __name__ == "__main__":
    database_manager = DatabaseManager()
    key_storage = FileKeyStorage(SHARED_KEY_PATH)
    ip_resolver = IPResolver()
    connection_handler = ConnectionHandler()
    key_exchange = DiffieHellmanKeyExchange(key_length=2048, key_storage=key_storage)
    tcp_listener = TcpListener(connection_handler, key_exchange)
    message_sender = MessageSender()
    client_connection = ClientConnection(key_storage, ip_resolver, message_sender, database_manager)
    app = Application(database_manager, tcp_listener, client_connection)
    app.run()
