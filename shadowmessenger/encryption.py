from Crypto.Cipher import AES
import base64
from Crypto.Random import get_random_bytes
import os

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
