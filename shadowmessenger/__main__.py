#!/usr/bin/python3

import socket
import threading
import os

from shadowmessenger import encryption
from shadowmessenger import messaging


def main_loop(encryption_handler: encryption.EncryptionHandler):
    """
    Main loop to handle connections and communication.

    :param encryption_handler: EncryptionHandler instance
    """
    conn_gen = messaging.connection_generator()

    username, target_ip = next(conn_gen)
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((str(target_ip), 13377))
            threading.Thread(
                target=messaging.send_tcp_message,
                args=(sock, username, encryption_handler),
            ).start()
            break
        except Exception as e:
            print(f"Failed to connect to {target_ip}: {e}")
            username, target_ip = next(conn_gen)


def main():
    """
    Main entry point for the script.
    """
    key = encryption.load_key()
    encryption_handler = encryption.EncryptionHandler(key)
    listen_thread = threading.Thread(
        target=messaging.listen_tcp, args=(encryption_handler,), daemon=True
    )
    listen_thread.start()
    main_loop(encryption_handler)


if __name__ == "__main__":
    main()
