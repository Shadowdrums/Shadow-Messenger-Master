import pytest
from shadowmessenger.master import EncryptionHandler

@pytest.fixture
def encryption_handler():
    return EncryptionHandler(key=b'Sixteen byte key')

def test_encrypt_decrypt(encryption_handler):
    message = "Henlo worlmd!"
    encrypted_message = encryption_handler.encrypt(message)
    decrypted_message = encryption_handler.decrypt(encrypted_message)
    assert decrypted_message == message
