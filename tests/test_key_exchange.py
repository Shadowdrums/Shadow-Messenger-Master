import pytest
from shadowmessenger.master import DiffieHellman, derive_key, combine_key_halves

@pytest.fixture
def diffie_hellman_instances():
    """
    Fixture to create DiffieHellman instances for server and client with the same p and g values.

    :return: Tuple of server and client DiffieHellman instances.
    """
    dh_common_prime, dh_common_base = DiffieHellman().get_params()
    server_dh = DiffieHellman(p=dh_common_prime, g=dh_common_base)
    client_dh = DiffieHellman(p=dh_common_prime, g=dh_common_base)
    return server_dh, client_dh

def test_diffie_hellman_key_exchange(diffie_hellman_instances):
    """
    Test to verify the Diffie-Hellman key exchange process.

    :param diffie_hellman_instances: Tuple of server and client DiffieHellman instances.
    """
    server_dh, client_dh = diffie_hellman_instances

    server_public_key = server_dh.generate_public_key()
    client_public_key = client_dh.generate_public_key()

    assert server_public_key is not None
    assert client_public_key is not None

    server_shared_secret = server_dh.generate_shared_secret(client_public_key)
    client_shared_secret = client_dh.generate_shared_secret(server_public_key)

    assert server_shared_secret == client_shared_secret

def test_derive_key(diffie_hellman_instances):
    """
    Test to verify the key derivation from the shared secret.

    :param diffie_hellman_instances: Tuple of server and client DiffieHellman instances.
    """
    server_dh, client_dh = diffie_hellman_instances

    server_public_key = server_dh.generate_public_key()
    client_public_key = client_dh.generate_public_key()

    server_shared_secret = server_dh.generate_shared_secret(client_public_key)
    derived_key = derive_key(server_shared_secret)

    assert len(derived_key) == 32

def test_combine_key_halves(diffie_hellman_instances):
    """
    Test to verify the combination of key halves and shared secret to derive the final key.

    :param diffie_hellman_instances: Tuple of server and client DiffieHellman instances.
    """
    server_dh, client_dh = diffie_hellman_instances

    server_public_key = server_dh.generate_public_key()
    client_public_key = client_dh.generate_public_key()

    server_shared_secret = server_dh.generate_shared_secret(client_public_key)

    key_half1 = b'1234567890123456'
    key_half2 = b'6543210987654321'
    combined_key = combine_key_halves(key_half1, key_half2, str(server_shared_secret).encode())

    assert len(combined_key) == 32

if __name__ == "__main__":
    pytest.main()
