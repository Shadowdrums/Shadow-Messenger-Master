import pytest
from shadowmessenger.master import ProtocolMessage, EncryptionHandler

@pytest.fixture
def encryption_handler():
    """
    Fixture to create an EncryptionHandler instance with a test key.
    """
    return EncryptionHandler(key=b'Sixteen byte key')

def test_protocol_message(encryption_handler):
    """
    Test the creation and parsing of ProtocolMessage objects.

    Verifies that a message can be correctly encrypted to bytes and decrypted back to a ProtocolMessage object.
    """
    message = ProtocolMessage("HELLO", "testuser", "###hello###")
    encrypted_message = message.to_bytes(encryption_handler)
    decrypted_message = ProtocolMessage.from_bytes(encrypted_message, encryption_handler)
    assert decrypted_message == message

def test_protocol_message_types(encryption_handler):
    """
    Test the creation of different types of ProtocolMessage objects.

    Verifies that HELLO, KEEP_ALIVE, and ACK messages are created with the correct attributes.
    """
    hello_message = ProtocolMessage.hello_message("testuser")
    keep_alive_message = ProtocolMessage.keep_alive_message("testuser")
    ack_message = ProtocolMessage.ack_message("testuser")
    assert hello_message.message_type == "HELLO"
    assert keep_alive_message.message_type == "KEEP_ALIVE"
    assert ack_message.message_type == "ACK"
    assert hello_message.content == "###hello###"
    assert keep_alive_message.content == "###keepalive###"
    assert ack_message.content == "###ack###"

def test_protocol_message_parsing_failure(encryption_handler):
    """
    Test the handling of invalid message formats.

    Verifies that from_bytes returns None when provided with invalid data.
    """
    invalid_data = b'invalid_message_format'
    parsed_message = ProtocolMessage.from_bytes(invalid_data, encryption_handler)
    assert parsed_message is None

def test_protocol_message_real_values(encryption_handler):
    """
    Test the creation and parsing of a real-world ProtocolMessage.

    Verifies that a MESSAGE type ProtocolMessage can be correctly encrypted and decrypted.
    """
    message = ProtocolMessage("MESSAGE", "realuser", "This is a real message.")
    encrypted_message = message.to_bytes(encryption_handler)
    decrypted_message = ProtocolMessage.from_bytes(encrypted_message, encryption_handler)
    assert decrypted_message == message
    assert decrypted_message.message_type == "MESSAGE"
    assert decrypted_message.username == "realuser"
    assert decrypted_message.content == "This is a real message."

if __name__ == "__main__":
    pytest.main()