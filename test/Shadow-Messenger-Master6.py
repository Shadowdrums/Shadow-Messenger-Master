import socket
import threading
import ipaddress
import os
import time
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import number
from dataclasses import dataclass
import base64
import sqlite3
from hashlib import sha256

# Encryption Handler
class EncryptionHandler:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, message: str) -> str:
        cipher = AES.new(self.key, AES.MODE_CFB)
        iv = cipher.iv
        encrypted_message = cipher.encrypt(message.encode())
        iv_encrypted_message = iv + encrypted_message
        b64_message = base64.b64encode(iv_encrypted_message).decode('utf-8')
        return b64_message

    def decrypt(self, b64_message: str) -> str:
        try:
            iv_encrypted_message = base64.b64decode(b64_message)
            iv = iv_encrypted_message[:16]
            encrypted_message = iv_encrypted_message[16:]
            cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
            decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
            return decrypted_message
        except Exception as e:
            print(f"Decryption failed: {e}")
            return ""

# Message Protocol
@dataclass
class ProtocolMessage:
    message_type: str
    username: str
    content: str

    def to_bytes(self, encryption_handler: EncryptionHandler) -> bytes:
        message = f"{self.message_type}:{self.username}:{self.content}"
        return encryption_handler.encrypt(message).encode('utf-8')

    @staticmethod
    def from_bytes(data: bytes, encryption_handler: EncryptionHandler):
        decrypted_message = encryption_handler.decrypt(data.decode('utf-8'))
        if not decrypted_message:
            return None
        try:
            message_type, username, content = decrypted_message.split(":", 2)
            return ProtocolMessage(message_type, username, content)
        except ValueError as e:
            print(f"Failed to parse message: {e}")
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

# Diffie-Hellman Key Exchange
class DiffieHellman:
    def __init__(self, key_length=2048):
        self.key_length = key_length
        self.private_key = number.getPrime(self.key_length)
        self.p = number.getPrime(self.key_length)
        self.g = number.getPrime(self.key_length)

    def generate_public_key(self):
        return pow(self.g, self.private_key, self.p)

    def generate_shared_secret(self, other_public_key):
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return sha256(str(shared_secret).encode()).digest()

# Main Routine
KEEP_ALIVE_INTERVAL = 10  # seconds
TIMEOUT = 30  # seconds

def generate_master_key() -> bytes:
    key = get_random_bytes(32)
    with open('master.key', 'wb') as key_file:
        key_file.write(key)
    return key

def load_master_key() -> bytes:
    if os.path.exists('master.key'):
        with open('master.key', 'rb') as key_file:
            key = key_file.read()
    else:
        key = generate_master_key()
    return key

def send_keep_alive(sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
    while True:
        time.sleep(KEEP_ALIVE_INTERVAL)
        try:
            sock.sendall(ProtocolMessage.keep_alive_message(username).to_bytes(encryption_handler))
        except Exception as e:
            print(f"Failed to send keep-alive message: {str(e)}")
            break

def send_tcp_message(sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
    try:
        sock.sendall(ProtocolMessage.hello_message(username).to_bytes(encryption_handler))
        threading.Thread(target=send_keep_alive, args=(sock, username, encryption_handler), daemon=True).start()
        while True:
            message = input("Enter the message you want to send (or type 'exit' to close): ")
            if message.lower() == 'exit':
                break
            msg = ProtocolMessage("MESSAGE", username, message)
            sock.sendall(msg.to_bytes(encryption_handler))
            print("Message sent successfully!")
    except Exception as e:
        print(f"Failed to send message: {str(e)}")

def handle_connection(conn: socket.socket, addr, encryption_handler: EncryptionHandler):
    print(f"\nConnection received from {addr[0]}:{addr[1]}")
    try:
        conn.settimeout(TIMEOUT)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = ProtocolMessage.from_bytes(data, encryption_handler)
            if message is None:
                continue
            if message.message_type == "HELLO":
                print(f"\nRemote client {addr[0]}:{addr[1]} connected successfully.")
            elif message.message_type == "KEEP_ALIVE":
                conn.sendall(ProtocolMessage.ack_message(message.username).to_bytes(encryption_handler))
            elif message.message_type == "ACK":
                print(f"\nReceived acknowledgment from {addr[0]}:{addr[1]}")
            else:
                print(f"\nReceived message from {message.username}: {message.content}")
                with open(os.path.join(os.getcwd(), 'received_messages.txt'), 'a') as f:
                    f.write(f"{addr[0]}:{addr[1]} - {message.username}: {message.content}\n")
                response = input("Enter your response: ")
                if response.lower() == 'exit':
                    break
                response_msg = ProtocolMessage("MESSAGE", "Server", response)
                conn.sendall(response_msg.to_bytes(encryption_handler))
    except socket.timeout:
        print(f"Connection with {addr[0]}:{addr[1]} timed out.")
    except Exception as e:
        print(f"Error during receiving message: {str(e)}")
    finally:
        conn.close()

def listen_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 13377))
    sock.listen()
    print("Listening on port 13377...")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=diffie_hellman_key_exchange, args=(conn, addr)).start()

def resolve_ip(target_ip: str):
    if not isinstance(target_ip, str):
        raise TypeError("Input for resolve_ip was not a string value!")
    try:
        resolved_ip = socket.gethostbyname(target_ip)
        return resolved_ip
    except socket.gaierror:
        raise ValueError(f"Invalid IP address or hostname: {target_ip}")

def setup_database():
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        destination_ip TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()

def insert_user(username, password, destination_ip, encryption_handler):
    hashed_password = hash_password(password)
    encrypted_ip = encryption_handler.encrypt(destination_ip)
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, destination_ip) VALUES (?, ?, ?)", (username, hashed_password, encrypted_ip))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, password, destination_ip FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def verify_user(username, password):
    user = get_user(username)
    if user:
        hashed_password = hash_password(password)
        return hashed_password == user[1]
    return False

def get_user_ips(username, encryption_handler):
    conn = sqlite3.connect('user_data.db')
    cursor = conn.cursor()
    cursor.execute("SELECT destination_ip FROM users WHERE username = ?",```python
    cursor.execute("SELECT destination_ip FROM users WHERE username = ?", (username,))
    ips = cursor.fetchall()
    conn.close()
    return [encryption_handler.decrypt(ip[0]) for ip in ips]

def user_input_generator(encryption_handler):
    while True:
        print("1. Existing User\n2. New User")
        choice = input("Select an option: ")

        if choice == '1':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            if verify_user(username, password):
                print(f"Welcome back, {username}!")
                ips = get_user_ips(username, encryption_handler)
                if ips:
                    print("Select an IP address:")
                    for i, ip in enumerate(ips, 1):
                        print(f"{i}. {ip}")
                    ip_choice = int(input("Enter the number of the IP or 0 to add a new one: "))
                    if ip_choice == 0:
                        target_ip = input("Enter the new IP address: ")
                        try:
                            resolved_ip = resolve_ip(target_ip)
                            insert_user(username, password, resolved_ip, encryption_handler)
                        except ValueError as e:
                            print(e)
                            continue
                    else:
                        resolved_ip = ips[ip_choice - 1]
                else:
                    target_ip = input("Enter the IP address of the target machine: ")
                    try:
                        resolved_ip = resolve_ip(target_ip)
                        insert_user(username, password, resolved_ip, encryption_handler)
                    except ValueError as e:
                        print(e)
                        continue
                yield username, resolved_ip
            else:
                print("Invalid username or password. Please try again.")
        elif choice == '2':
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            target_ip = input("Enter the IP address of the target machine: ")
            try:
                resolved_ip = resolve_ip(target_ip)
                insert_user(username, password, resolved_ip, encryption_handler)
                print(f"User {username} created successfully.")
                yield username, resolved_ip
            except ValueError as e:
                print(e)
        else:
            print("Invalid choice. Please select 1 or 2.")

def connection_generator(encryption_handler):
    input_gen = user_input_generator(encryption_handler)
    while True:
        username, target_ip = next(input_gen)
        yield username, target_ip

def diffie_hellman_key_exchange(conn, addr):
    dh = DiffieHellman()
    public_key = dh.generate_public_key()
    conn.sendall(str(public_key).encode('utf-8'))
    other_public_key = int(conn.recv(1024).decode('utf-8'))
    shared_secret = dh.generate_shared_secret(other_public_key)
    encryption_handler = EncryptionHandler(shared_secret)
    handle_connection(conn, addr, encryption_handler)

def main_loop():
    master_key = load_master_key()
    encryption_handler = EncryptionHandler(master_key)
    conn_gen = connection_generator(encryption_handler)
    username, target_ip = next(conn_gen)
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((str(target_ip), 13377))
            dh = DiffieHellman()
            public_key = dh.generate_public_key()
            sock.sendall(str(public_key).encode('utf-8'))
            other_public_key = int(sock.recv(1024).decode('utf-8'))
            shared_secret = dh.generate_shared_secret(other_public_key)
            encryption_handler = EncryptionHandler(shared_secret)
            threading.Thread(target=send_tcp_message, args=(sock, username, encryption_handler)).start()
            break
        except Exception as e:
            print(f"Failed to connect to {target_ip}: {e}")
            username, target_ip = next(conn_gen)

def main():
    setup_database()
    listen_thread = threading.Thread(target=listen_tcp, daemon=True)
    listen_thread.start()
    main_loop()

if __name__ == "__main__":
    main()
