import socket
import threading
import logging
import time
import queue

from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import HKDF

from shadowmsg import TIMEOUT, KEEP_ALIVE_INTERVAL, PORT
from shadowmsg.protocol import ProtocolMessage
from shadowmsg.encryption import EncryptionHandler
from shadowmsg.database import DatabaseManager


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
                salt=b'',
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
        sock.bind(("0.0.0.0", PORT))  # Bind to all network interfaces
        sock.listen()
        logging.info(f"Listening on port {PORT}...")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=self.key_exchange.perform_key_exchange,
                             args=(conn, addr, self.connection_handler)).start()


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


class MessageSender:
    @staticmethod
    def send_keep_alive(sock: socket.socket, username: str, encryption_handler: EncryptionHandler):
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
            threading.Thread(target=self.send_keep_alive, args=(sock, username, encryption_handler),
                             daemon=True).start()
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

    @staticmethod
    def receive_all(sock, length):
        data = b''
        while len(data) < length:
            more = sock.recv(length - len(data))
            if not more:
                raise EOFError(f"Expected {length} bytes but only received {len(data)} bytes before the socket closed")
            data += more
        return data

    def listen_for_messages(self, sock: socket.socket, encryption_handler: EncryptionHandler,
                            message_queue: queue.Queue):
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

    @staticmethod
    def display_messages(message_queue: queue.Queue):
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
                    salt=b'',
                    hashmod=SHA256,
                    context=b'handshake data'
                )
                logging.debug(f"Derived key: {full_key.hex()}")

                self.database_manager.store_key(username, full_key)

                encryption_handler = EncryptionHandler(full_key)

                # Queue to handle message display
                message_queue = queue.Queue()

                # Start a thread to listen for incoming messages
                listen_thread = threading.Thread(target=self.listen_for_messages,
                                                 args=(sock, encryption_handler, message_queue))
                listen_thread.start()

                # Start a thread to display messages from the queue
                display_thread = threading.Thread(target=self.display_messages, args=(message_queue,))
                display_thread.start()

                # Handle user input and send messages in a separate thread
                user_input_thread = threading.Thread(target=self.user_input_handler,
                                                     args=(sock, username, encryption_handler))
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
