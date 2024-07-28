import socket
import threading
import time
import logging
from dataclasses import dataclass
import sqlite3
from hashlib import sha256
from typing import Optional, List
from os import urandom
from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import queue
import getpass
import configparser

KEEP_ALIVE_INTERVAL = 300  # 5 minutes
TIMEOUT = 600  # 10 minutes
PORT = 21337

# AES encryption and decryption
def encrypt_message(key, message, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

def decrypt_message(key, encrypted_message, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message

@dataclass
class User:
    username: str
    password: str
    destination_ip: str

class EncryptionHandler:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, message: str) -> bytes:
        iv = get_random_bytes(16)
        encrypted_message = encrypt_message(self.key, message.encode('utf-8'), iv)
        logging.debug(f"Encrypting message: {message} | IV: {iv.hex()} | Encrypted: {encrypted_message.hex()}")
        return iv + encrypted_message

    def decrypt(self, encrypted_message: bytes) -> str:
        try:
            iv = encrypted_message[:16]
            encrypted_message = encrypted_message[16:]
            decrypted_message = decrypt_message(self.key, encrypted_message, iv).decode('utf-8')
            logging.debug(f"Decrypting message: {encrypted_message.hex()} | IV: {iv.hex()} | Decrypted: {decrypted_message}")
            return decrypted_message
        except Exception as e:
            logging.error(f"Decryption failed: {e} | Encrypted Message: {encrypted_message.hex()}")
            return ""

@dataclass
class ProtocolMessage:
    message_type: str
    username: str
    content: str

    def to_bytes(self, encryption_handler: EncryptionHandler) -> bytes:
        message = f"{self.message_type}:{self.username}:{self.content}"
        return encryption_handler.encrypt(message)

    @staticmethod
    def from_bytes(data: bytes, encryption_handler: EncryptionHandler) -> Optional["ProtocolMessage"]:
        decrypted_message = encryption_handler.decrypt(data)
        if not decrypted_message:
            return None
        try:
            message_type, username, content = decrypted_message.split(":", 2)
            return ProtocolMessage(message_type, username, content)
        except ValueError as e:
            logging.error(f"Failed to parse message: {e} | Decrypted Message: {decrypted_message}")
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

@dataclass
class DatabaseManager:
    db_path: str = "user_data.db"
    retries: int = 5
    delay: float = 0.5

    def __post_init__(self):
        self.setup_database()

    def setup_database(self):
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

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

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

    def hash_password(self, password: str) -> str:
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

class ConnectionHandler:
    def __init__(self, database_manager: DatabaseManager):
        self.database_manager = database_manager

    def handle_connection(self, conn: socket.socket, addr, encryption_handler: EncryptionHandler):
        logging.info(f"\nConnection received from {addr[0]}:{addr[1]}")
        try:
            conn.settimeout(TIMEOUT)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                logging.debug(f"Received encrypted data: {data.hex()}")
                message = ProtocolMessage.from_bytes(data, encryption_handler)
                if message is None:
                    continue
                if message.message_type == "HELLO":
                    logging.info(f"\nRemote client {addr[0]}:{addr[1]} connected successfully.")
                    # Save the contact information
                    self.database_manager.insert_contact("username_placeholder", message.username, addr[0])
                elif message.message_type == "KEEP_ALIVE":
                    conn.sendall(ProtocolMessage.ack_message(message.username).to_bytes(encryption_handler))
                    logging.debug("Sent acknowledgment for keep-alive message.")
                elif message.message_type == "ACK":
                    logging.debug(f"Received acknowledgment from {addr[0]}:{addr[1]}")
                else:
                    logging.info(f"Received message from {message.username}: {message.content}")
                    with open("received_messages.txt", "a") as f:
                        f.write(f"{addr[0]}:{addr[1]} - {message.username}: {message.content}\n")
        except socket.timeout:
            logging.info(f"Connection with {addr[0]}:{addr[1]} timed out.")
        except Exception as e:
            logging.error(f"Error during receiving message: {str(e)}")
        finally:
            conn.close()

class DiffieHellmanKeyExchange:
    def __init__(self, database_manager: DatabaseManager):
        self.database_manager = database_manager
        self.dh_key = DSA.generate(2048)
        self.dh_parameters = (self.dh_key.p, self.dh_key.q, self.dh_key.g)

    def perform_key_exchange(self, conn: socket.socket, addr, connection_handler: ConnectionHandler):
        try:
            # Send public parameters to the client
            parameters_bytes = self.dh_parameters[0].to_bytes(256, byteorder='big') + \
                               self.dh_parameters[1].to_bytes(32, byteorder='big') + \
                               self.dh_parameters[2].to_bytes(256, byteorder='big')
            conn.sendall(parameters_bytes)
            logging.debug(f"Sent parameters to client")

            # Receive client's public key
            client_public_key_bytes = conn.recv(256)
            client_public_key = int.from_bytes(client_public_key_bytes, byteorder='big')
            logging.debug(f"Received public key from client: {client_public_key}")

            # Generate server's public and private key
            server_private_key = random.StrongRandom().randint(1, self.dh_parameters[0] - 1)
            server_public_key = pow(self.dh_parameters[2], server_private_key, self.dh_parameters[0])

            # Send server's public key to the client
            conn.sendall(server_public_key.to_bytes(256, byteorder='big'))
            logging.debug(f"Sent public key to client: {server_public_key}")

            # Compute shared secret
            shared_secret = pow(client_public_key, server_private_key, self.dh_parameters[0])
            shared_secret_bytes = shared_secret.to_bytes(256, byteorder='big')
            logging.debug(f"Shared secret (server): {shared_secret}")

            # Generate the encryption key using HKDF
            full_key = HKDF(
                master=shared_secret_bytes,
                key_len=32,
                salt=None,
                hashmod=SHA256,
                context=b'handshake data'
            )
            logging.debug(f"Derived key: {full_key.hex()}")

            self.database_manager.store_key(addr[0], full_key)

            encryption_handler = EncryptionHandler(full_key)
            connection_handler.handle_connection(conn, addr, encryption_handler)
        except Exception as e:
            logging.error(f"Error during Diffie-Hellman key exchange: {str(e)}")
        finally:
            conn.close()

class TcpListener:
    def __init__(self, connection_handler: ConnectionHandler, key_exchange: DiffieHellmanKeyExchange):
        self.connection_handler = connection_handler
        self.key_exchange = key_exchange

    def listen_tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", PORT))
        sock.listen()
        logging.info(f"Listening on port {PORT}...")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self.key_exchange.perform_key_exchange, args=(conn, addr, self.connection_handler)).start()

class IPResolver:
    def resolve_ip(self, target_ip: str) -> str:
        if not isinstance(target_ip, str):
            raise TypeError("Input for resolve_ip was not a string value!")
        try:
            resolved_ip = socket.gethostbyname(target_ip)
            logging.info(f"Resolved IP {target_ip} to {resolved_ip}")
            return resolved_ip
        except socket.gaierror:
            raise ValueError(f"Invalid IP address or hostname: {target_ip}")

class UserInputHandler:
    def __init__(self, database_manager: DatabaseManager, ip_resolver: IPResolver):
        self.database_manager = database_manager
        self.ip_resolver = ip_resolver
        self.encryption_handler = self._initialize_encryption_handler()

    def _initialize_encryption_handler(self) -> EncryptionHandler:
        key = self.database_manager.get_key("shared_key")
        if key is None:
            key = urandom(32)
            self.database_manager.store_key("shared_key", key)
        return EncryptionHandler(key)

    def get_user_input(self) -> tuple[str, str]:
        while True:
            choice = input("\n1. Login\n2. Register\nEnter your choice: ")
            if choice == "1":
                username = input("Enter your username: ")
                password = getpass.getpass("Enter your password: ")
                if self.database_manager.verify_user(username, password):
                    logging.info(f"User {username} logged in successfully.")
                    try:
                        user_ips = self.database_manager.get_user_ips(username, self.encryption_handler)
                        if not user_ips:
                            raise ValueError("No IPs found for user.")
                        logging.info("Select the destination IP address:")
                        for i, ip in enumerate(user_ips):
                            logging.info(f"{i + 1}. {ip}")
                        logging.info(f"{len(user_ips) + 1}. Add a new IP")
                        selected_index = int(input("Enter your choice: ")) - 1
                        if selected_index == len(user_ips):
                            new_ip = input("Enter the new IP address: ")
                            resolved_ip = self.ip_resolver.resolve_ip(new_ip)
                            self.database_manager.add_ip_for_user(username, resolved_ip, self.encryption_handler)
                            return username, resolved_ip
                        elif selected_index < 0 or selected_index >= len(user_ips):
                            raise ValueError("Invalid choice.")
                        resolved_ip = self.ip_resolver.resolve_ip(user_ips[selected_index])
                        return username, resolved_ip
                    except ValueError as e:
                        logging.error(e)
                        continue
                else:
                    logging.error("Invalid username or password. Please try again.")
            elif choice == "2":
                username = input("Enter your username: ")
                password = getpass.getpass("Enter your password: ")
                target_ip = input("Enter the IP address of the target machine: ")
                try:
                    resolved_ip = self.ip_resolver.resolve_ip(target_ip)
                    logging.info(f"User {username} created successfully.")
                    _user = User(username, password, resolved_ip)
                    self.database_manager.insert_user(_user, self.encryption_handler)
                    return username, resolved_ip
                except ValueError as e:
                    logging.error(e)
            else:
                logging.error("Invalid choice. Please select 1 or 2.")

class MessageSender:
    def send_keep_alive(self, sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
        while True:
            time.sleep(KEEP_ALIVE_INTERVAL)
            try:
                sock.sendall(ProtocolMessage.keep_alive_message(username).to_bytes(encryption_handler))
                logging.debug("Sent keep-alive message.")
            except Exception as e:
                logging.error(f"Failed to send keep-alive message: {str(e)}")
                break

    def send_tcp_message(self, sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
        try:
            threading.Thread(target=self.send_keep_alive, args=(sock, username, encryption_handler), daemon=True).start()
            while True:
                message = input("Enter the message you want to send (or type 'exit' to close): ")
                if message.lower() == "exit":
                    break
                msg = ProtocolMessage("MESSAGE", username, message)
                sock.sendall(msg.to_bytes(encryption_handler))
                logging.info("Message sent successfully!")
        except Exception as e:
            logging.error(f"Failed to send message: {str(e)}")

class ClientConnection:
    def __init__(self, database_manager: DatabaseManager, ip_resolver: IPResolver, message_sender: MessageSender):
        self.database_manager = database_manager
        self.ip_resolver = ip_resolver
        self.message_sender = message_sender
        self.keep_running = True

    def receive_all(self, sock, length):
        data = b''
        while len(data) < length:
            more = sock.recv(length - len(data))
            if not more:
                raise EOFError(f"Expected {length} bytes but only received {len(data)} bytes before the socket closed")
            data += more
        return data

    def listen_for_messages(self, sock: socket.socket, encryption_handler: EncryptionHandler, message_queue: queue.Queue):
        try:
            while self.keep_running:
                data = sock.recv(1024)
                if not data:
                    break
                logging.debug(f"Received encrypted data: {data.hex()}")
                message = ProtocolMessage.from_bytes(data, encryption_handler)
                if message and message.message_type == "MESSAGE":
                    logging.info(f"\nReceived message from {message.username}: {message.content}")
                    message_queue.put(f"Received message from {message.username}: {message.content}")
        except socket.error as e:
            logging.error(f"Error receiving message: {str(e)}")
        finally:
            message_queue.put(None)

    def user_input_handler(self, sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
        try:
            while self.keep_running:
                message = input("Enter the message you want to send (or type 'exit' to close): ")
                if message.lower() == "exit":
                    self.keep_running = False
                    break
                msg = ProtocolMessage("MESSAGE", username, message)
                sock.sendall(msg.to_bytes(encryption_handler))
                logging.info("Message sent successfully!")
        except Exception as e:
            logging.error(f"Failed to send message: {str(e)}")
        finally:
            sock.close()

    def display_messages(self, message_queue: queue.Queue):
        while True:
            message = message_queue.get()
            if message is None:
                break
            print(message)

    def connect_and_communicate(self, username: str, target_ip: str):
        while self.keep_running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                logging.info(f"Attempting to connect to {target_ip}:{PORT}")
                sock.connect((self.ip_resolver.resolve_ip(target_ip), PORT))

                # Receive server's parameters
                parameters_bytes = sock.recv(544)
                p = int.from_bytes(parameters_bytes[:256], byteorder='big')
                q = int.from_bytes(parameters_bytes[256:288], byteorder='big')
                g = int.from_bytes(parameters_bytes[288:], byteorder='big')
                dh_parameters = (p, q, g)

                # Generate client's public and private key
                client_private_key = random.StrongRandom().randint(1, p - 1)
                client_public_key = pow(g, client_private_key, p)

                # Send client's public key to server
                sock.sendall(client_public_key.to_bytes(256, byteorder='big'))
                logging.debug(f"Sent public key to server: {client_public_key}")

                # Receive server's public key
                server_public_key_bytes = sock.recv(256)
                server_public_key = int.from_bytes(server_public_key_bytes, byteorder='big')
                logging.debug(f"Received public key from server: {server_public_key}")

                # Compute shared secret
                shared_secret = pow(server_public_key, client_private_key, p)
                shared_secret_bytes = shared_secret.to_bytes(256, byteorder='big')
                logging.debug(f"Shared secret (client): {shared_secret}")

                # Generate the encryption key using HKDF
                full_key = HKDF(
                    master=shared_secret_bytes,
                    key_len=32,
                    salt=None,
                    hashmod=SHA256,
                    context=b'handshake data'
                )
                logging.debug(f"Derived key: {full_key.hex()}")

                self.database_manager.store_key(username, full_key)

                encryption_handler = EncryptionHandler(full_key)

                # Queue to handle message display
                message_queue = queue.Queue()

                # Start a thread to listen for incoming messages
                listen_thread = threading.Thread(target=self.listen_for_messages, args=(sock, encryption_handler, message_queue))
                listen_thread.start()

                # Start a thread to display messages from the queue
                display_thread = threading.Thread(target=self.display_messages, args=(message_queue,))
                display_thread.start()

                # Handle user input and send messages in a separate thread
                user_input_thread = threading.Thread(target=self.user_input_handler, args=(sock, username, encryption_handler))
                user_input_thread.start()

                user_input_thread.join()  # Wait for the user input thread to finish
                self.keep_running = False  # Signal other threads to stop

                message_queue.put(None)  # Signal the display thread to exit
                listen_thread.join()
                display_thread.join()
                break
            except Exception as e:
                logging.error(f"Failed to connect to {target_ip}: {e}")
                if not self.keep_running:
                    break
                time.sleep(5)  # Wait before retrying
            finally:
                if sock:
                    sock.close()

class Application:
    def __init__(self, tcp_listener: TcpListener, client_connection: ClientConnection):
        self.tcp_listener = tcp_listener
        self.client_connection = client_connection
        self.database_manager = self.client_connection.database_manager

    def run(self):
        self.database_manager.setup_database()
        user_input_handler = UserInputHandler(self.database_manager, IPResolver())
        username, target_ip = user_input_handler.get_user_input()
        threading.Thread(target=self.tcp_listener.listen_tcp, daemon=True).start()
        time.sleep(1)  # Ensure listener thread starts properly
        self.client_connection.connect_and_communicate(username, target_ip)

def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    database_manager = DatabaseManager()
    ip_resolver = IPResolver()
    connection_handler = ConnectionHandler(database_manager=database_manager)
    key_exchange = DiffieHellmanKeyExchange(database_manager=database_manager)
    tcp_listener = TcpListener(connection_handler, key_exchange)
    message_sender = MessageSender()
    client_connection = ClientConnection(database_manager=database_manager, ip_resolver=ip_resolver, message_sender=message_sender)
    app = Application(tcp_listener, client_connection)
    app.run()

if __name__ == "__main__":
    main()
