from dataclasses import dataclass
from typing import Optional
import logging

from shadowmsg.encryption import EncryptionHandler


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
