import threading
import time
import logging
import subprocess  # To run the banner.py script

from shadowmsg.database import DatabaseManager
from shadowmsg.network import TcpListener, ClientConnection, ConnectionHandler, DiffieHellmanKeyExchange, MessageSender, \
    IPResolver
from shadowmsg.user_input import UserInputHandler
from shadowmsg.banner import run_banner


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
    database_manager.setup_database()  # Ensure database is set up before running the banner

    # Run banner.py and display welcome message
    run_banner()
    print("Welcome to Shadow-Messenger-Master")

    ip_resolver = IPResolver()
    connection_handler = ConnectionHandler(database_manager=database_manager)
    key_exchange = DiffieHellmanKeyExchange(database_manager=database_manager)
    tcp_listener = TcpListener(connection_handler, key_exchange)
    message_sender = MessageSender()
    client_connection = ClientConnection(database_manager=database_manager, ip_resolver=ip_resolver,
                                         message_sender=message_sender)
    app = Application(tcp_listener, client_connection)
    app.run()
