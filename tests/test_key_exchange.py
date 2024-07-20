import pytest
from shadowmessenger.master import DiffieHellman

def test_diffie_hellman():
    dh1 = DiffieHellman()
    dh2 = DiffieHellman(p=dh1.p, g=dh1.g)
    public_key1 = dh1.generate_public_key()
    public_key2 = dh2.generate_public_key()
    shared_secret1 = dh1.generate_shared_secret(public_key2)
    shared_secret2 = dh2.generate_shared_secret(public_key1)
    assert shared_secret1 == shared_secret2
