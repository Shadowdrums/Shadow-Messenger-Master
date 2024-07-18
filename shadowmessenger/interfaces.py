from abc import ABC, abstractmethod
import socket
from typing import Optional

class IEncryptionHandler(ABC):
    @abstractmethod
    def encrypt(self, message: str) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, encrypted_message: bytes) -> str:
        pass


class IConnectionHandler(ABC):
    @abstractmethod
    def handle_connection(
        self, conn: socket.socket, addr, encryption_handler: IEncryptionHandler
    ):
        pass


class IDiffieHellmanKeyExchange(ABC):
    @abstractmethod
    def perform_key_exchange(
        self, conn: socket.socket, addr, connection_handler: IConnectionHandler
    ):
        pass


class IDiffieHellman(ABC):
    @abstractmethod
    def get_params(self) -> tuple[int, int]:
        pass

    @abstractmethod
    def generate_public_key(self) -> int:
        pass

    @abstractmethod
    def generate_shared_secret(self, other_public_key: int) -> int:
        pass


class IKeyStorage(ABC):
    @abstractmethod
    def save_key(self, key: bytes):
        pass

    @abstractmethod
    def load_key(self) -> Optional[bytes]:
        pass


class IMessageSender(ABC):
    @abstractmethod
    def send_keep_alive(
        self, sock: socket.socket, username: str, encryption_handler: IEncryptionHandler
    ):
        pass

    @abstractmethod
    def send_tcp_message(
        self, sock: socket.socket, username: str, encryption_handler: IEncryptionHandler
    ):
        pass


class ITcpListener(ABC):
    @abstractmethod
    def listen_tcp(self):
        pass


class IIPResolver(ABC):
    @abstractmethod
    def resolve_ip(self, target_ip: str) -> str:
        pass


class IDatabaseManager(ABC):
    @abstractmethod
    def setup_database(self):
        pass

    @abstractmethod
    def insert_user(
        self,
        username,
        password,
        destination_ip,
        encryption_handler: Optional[IEncryptionHandler],
    ):
        pass

    @abstractmethod
    def get_user(self, username) -> Optional[tuple[str, str, str]]:
        pass

    @abstractmethod
    def verify_user(self, username, password) -> bool:
        pass

    @abstractmethod
    def get_user_ips(
        self, username, encryption_handler: Optional[IEncryptionHandler]
    ) -> list[str]:
        pass


class IUserInputHandler(ABC):
    @abstractmethod
    def get_user_input(self) -> tuple[str, str]:
        pass



class IClientConnection(ABC):
    @abstractmethod
    def connect_and_communicate(self, username: str, target_ip: str):
        pass
