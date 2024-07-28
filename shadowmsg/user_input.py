import getpass
import logging
from os import urandom

from shadowmsg.encryption import EncryptionHandler
from shadowmsg.database import DatabaseManager, User
from shadowmsg.network import IPResolver


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
