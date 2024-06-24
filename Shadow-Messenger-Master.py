#!/usr/bin/python3

# Main deps
import socket
import threading
import ipaddress
import os
import time
from Crypto.Random import get_random_bytes

# Message protocol deps
from dataclasses import dataclass

# Encryption handler deps
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Encryption Handler
class EncryptionHandler:
    def __init__(self, key: bytes):
        """
        Initialize the EncryptionHandler with the given encryption key.

        :param key: Encryption key (bytes)
        """
        self.key = key

    def encrypt(self, message: str) -> bytes:
        """
        Encrypt the given message using AES encryption.

        :param message: Message to encrypt (str)
        :return: Encrypted message (bytes)
        """
        cipher = AES.new(self.key, AES.MODE_CFB)
        iv = cipher.iv
        encrypted_message = cipher.encrypt(message.encode())
        iv_encrypted_message = iv + encrypted_message
        b64_message = base64.b64encode(iv_encrypted_message)
        return b64_message

    def decrypt(self, b64_message: bytes) -> str:
        """
        Decrypt the given encrypted message using AES decryption.

        :param b64_message: Encrypted message (bytes)
        :return: Decrypted message (str)
        """
        try:
            iv_encrypted_message = base64.b64decode(b64_message)
            iv = iv_encrypted_message[:16]
            encrypted_message = iv_encrypted_message[16:]
            cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
            decrypted_message = cipher.decrypt(encrypted_message).decode()
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
        """
        Serialize the ProtocolMessage to bytes, encrypting the content.

        :param encryption_handler: EncryptionHandler instance
        :return: Encrypted message (bytes)
        """
        message = f"{self.message_type}:{self.username}:{self.content}"
        return encryption_handler.encrypt(message)

    @staticmethod
    def from_bytes(data: bytes, encryption_handler: EncryptionHandler):
        """
        Deserialize bytes into a ProtocolMessage, decrypting the content.

        :param data: Encrypted message (bytes)
        :param encryption_handler: EncryptionHandler instance
        :return: ProtocolMessage instance or None if decryption fails
        """
        decrypted_message = encryption_handler.decrypt(data)
        if not decrypted_message:
            return None
        message_type, username, content = decrypted_message.split(":", 2)
        return ProtocolMessage(message_type, username, content)

    @classmethod
    def hello_message(cls, username):
        """
        Create a HELLO ProtocolMessage.

        :param username: Username (str)
        :return: ProtocolMessage instance
        """
        return cls("HELLO", username, "###henlo###")

    @classmethod
    def keep_alive_message(cls, username):
        """
        Create a KEEP_ALIVE ProtocolMessage.

        :param username: Username (str)
        :return: ProtocolMessage instance
        """
        return cls("KEEP_ALIVE", username, "###keepalive###")

    @classmethod
    def ack_message(cls, username):
        """
        Create an ACK ProtocolMessage.

        :param username: Username (str)
        :return: ProtocolMessage instance
        """
        return cls("ACK", username, "###ack###")

# Main Routine
KEEP_ALIVE_INTERVAL = 10  # seconds
TIMEOUT = 30  # seconds

def generate_key() -> bytes:
    """
    Generate a new encryption key and save it to 'master.key'.

    :return: Generated encryption key (bytes)
    """
    key = get_random_bytes(32)
    with open('master.key', 'wb') as key_file:
        key_file.write(key)
    return key

def load_key() -> bytes:
    """
    Load the encryption key from 'master.key', or generate a new one if it does not exist.

    :return: Encryption key (bytes)
    """
    if os.path.exists('master.key'):
        with open('master.key', 'rb') as key_file:
            key = key_file.read()
    else:
        key = generate_key()
    return key

def send_keep_alive(sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
    """
    Periodically send KEEP_ALIVE messages to maintain the connection.

    :param sock: Socket connection
    :param username: Username (str)
    :param encryption_handler: EncryptionHandler instance
    """
    while True:
        time.sleep(KEEP_ALIVE_INTERVAL)
        try:
            sock.sendall(ProtocolMessage.keep_alive_message(username).to_bytes(encryption_handler))
        except Exception as e:
            print(f"Failed to send keep-alive message: {str(e)}")
            break

def send_tcp_message(sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
    """
    Send messages to the target through the socket connection.

    :param sock: Socket connection
    :param username: Username (str)
    :param encryption_handler: EncryptionHandler instance
    """
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
    """
    Handle incoming connections and messages.

    :param conn: Connection socket
    :param addr: Address of the connected client
    :param encryption_handler: EncryptionHandler instance
    """
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
                response_msg = ProtocolMessage("MESSAGE", message.username, response)
                conn.sendall(response_msg.to_bytes(encryption_handler))
    except socket.timeout:
        print(f"Connection with {addr[0]}:{addr[1]} timed out.")
    except Exception as e:
        print(f"Error during receiving message: {str(e)}")
    finally:
        conn.close()

def listen_tcp(encryption_handler: EncryptionHandler):
    """
    Listen for incoming TCP connections.

    :param encryption_handler: EncryptionHandler instance
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 13377))
    sock.listen()
    print("Listening on port 13377...")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_connection, args=(conn, addr, encryption_handler)).start()

def resolve_ip(target_ip: str):
    """
    Resolve the given IP address.

    :param target_ip: Target IP address (str)
    :return: Resolved IP address (ipaddress.ip_address)
    :raises: TypeError if the input is not a string
    """
    if not isinstance(target_ip, str):
        raise TypeError("Input for resolve_ip was not a string value!")
    try:
        return ipaddress.ip_address(socket.gethostbyname(target_ip))
    except socket.gaierror:
        return ipaddress.ip_address(target_ip)

def user_input_generator():
    """
    Generator to get user inputs for username and target IP address.

    :yield: Tuple of username and target IP address (str, str)
    """
    while True:
        username = input("Enter your username: ")
        target_ip = input("Enter the IP address of the target machine: ")
        try:
            target_ip = resolve_ip(target_ip)
            with open(os.path.join(os.getcwd(), 'ip.txt'), 'w') as f:
                f.write(f"{username}:{target_ip}")
            yield username, target_ip
        except ValueError:
            print("Invalid IP address. Please try again.")

def connection_generator():
    """
    Generator to get connection details from the user.

    :yield: Tuple of username and target IP address (str, str)
    """
    input_gen = user_input_generator()
    while True:
        username, target_ip = next(input_gen)
        yield username, target_ip

def main_loop(encryption_handler: EncryptionHandler):
    """
    Main loop to handle connections and communication.

    :param encryption_handler: EncryptionHandler instance
    """
    conn_gen = connection_generator()

    while True:
        username, target_ip = next(conn_gen)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((str(target_ip), 13377))
            threading.Thread(target=send_tcp_message, args=(sock, username, encryption_handler)).start()
        except Exception as e:
            print(f"Failed to connect to {target_ip}: {e}")

def main():
    """
    Main entry point for the script.
    """
    key = load_key()
    encryption_handler = EncryptionHandler(key)
    listen_thread = threading.Thread(target=listen_tcp, args=(encryption_handler,), daemon=True)
    listen_thread.start()
    main_loop(encryption_handler)

if __name__ == "__main__":
    main()
