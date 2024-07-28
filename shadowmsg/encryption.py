from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import logging


def encrypt_message(key, message, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message


def decrypt_message(key, encrypted_message, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message


class EncryptionHandler:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, message: str) -> bytes:
        iv = get_random_bytes(16)
        encrypted_message = encrypt_message(self.key, message.encode('utf-8'), iv)
        logging.debug(f"Encrypting message: {message} | IV: {iv.hex()} | Encrypted: {encrypted_message.hex()}")
        return iv + encrypted_message

    def decrypt(self, encrypted_message: bytes) -> str:
        try:
            iv = encrypted_message[:16]
            encrypted_message = encrypted_message[16:]
            decrypted_message = decrypt_message(self.key, encrypted_message, iv).decode('utf-8')
            logging.debug(
                f"Decrypting message: {encrypted_message.hex()} | IV: {iv.hex()} | Decrypted: {decrypted_message}")
            return decrypted_message
        except Exception as e:
            logging.error(f"Decryption failed: {e} | Encrypted Message: {encrypted_message.hex()}")
            return ""
