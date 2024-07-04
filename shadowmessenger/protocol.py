from dataclasses import dataclass
from shadowmessenger.encryption import EncryptionHandler

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
        return cls("HELLO", username, "###hello###")

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