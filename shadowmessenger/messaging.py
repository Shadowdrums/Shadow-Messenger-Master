from shadowmessenger.protocol import ProtocolMessage
from shadowmessenger.encryption import EncryptionHandler
from shadowmessenger.config import MessengerConfig

import threading
import socket
import time
import os

CONFIG = MessengerConfig()

def user_input_generator():
    """
    Generator to get user inputs for username and target IP address.

    :yield: Tuple of username and target IP address (str, str)
    """
    while True:
        username = input("Enter your username: ")
        target_ip = input("Enter the IP address of the target machine: ")
        try:
            resolved_ip = resolve_ip(target_ip)
            with open(os.path.join(os.getcwd(), "ip.txt"), "w") as f:
                f.write(f"{username}:{resolved_ip}")
            yield username, resolved_ip
        except ValueError as e:
            print(e)


def connection_generator():
    """
    Generator to get connection details from the user.

    :yield: Tuple of username and target IP address (str, str)
    """
    input_gen = user_input_generator()
    while True:
        username, target_ip = next(input_gen)
        yield username, target_ip

def send_keep_alive(sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
    """
    Periodically send KEEP_ALIVE messages to maintain the connection.

    :param sock: Socket connection
    :param username: Username (str)
    :param encryption_handler: EncryptionHandler instance
    """
    while True:
        time.sleep(CONFIG.KEEP_ALIVE_INTERVAL)
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
        conn.settimeout(CONFIG.TIMEOUT)
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
    :return: Resolved IP address (str)
    :raises: TypeError if the input is not a string
    """
    if not isinstance(target_ip, str):
        raise TypeError("Input for resolve_ip was not a string value!")
    try:
        resolved_ip = socket.gethostbyname(target_ip)
        return resolved_ip
    except socket.gaierror:
        raise ValueError(f"Invalid IP address or hostname: {target_ip}")
