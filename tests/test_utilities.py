import pytest
from Crypto.Protocol.KDF import PBKDF2
from shadowmessenger.master import combine_key_halves

def test_combine_key_halves():
    """
    Test the combine_key_halves function with typical inputs.

    Verifies that:
    - The combined key length is 32 bytes.
    - Different inputs produce different combined keys.
    - The same inputs produce the same combined key.
    """
    key_half1 = b'1234567890123456'
    key_half2 = b'6543210987654321'
    shared_secret = b'shared_secret'
    
    combined_key = combine_key_halves(key_half1, key_half2, shared_secret)
    
    assert len(combined_key) == 32
    
    key_half1_diff = b'abcdef1234567890'
    key_half2_diff = b'0987654321fedcba'
    shared_secret_diff = b'another_shared_secret'
    
    combined_key_diff = combine_key_halves(key_half1_diff, key_half2_diff, shared_secret_diff)
    
    assert len(combined_key_diff) == 32
    assert combined_key_diff != combined_key
    combined_key_repeated = combine_key_halves(key_half1, key_half2, shared_secret)
    assert combined_key_repeated == combined_key

def test_combine_key_halves_consistency():
    """
    Test the consistency of the combine_key_halves function.

    Verifies that the same inputs consistently produce the same combined key.
    """
    key_half1 = b'1234567890123456'
    key_half2 = b'6543210987654321'
    shared_secret = b'shared_secret'

    combined_key_first = combine_key_halves(key_half1, key_half2, shared_secret)
    combined_key_second = combine_key_halves(key_half1, key_half2, shared_secret)
    
    assert combined_key_first == combined_key_second

def test_combine_key_halves_edge_cases():
    """
    Test the combine_key_halves function with edge case inputs.

    Verifies that the function handles edge cases correctly and the combined key length is 32 bytes.
    """
    key_half1 = b'0000000000000000'
    key_half2 = b'0000000000000000'
    shared_secret = b'0000000000000000'
    
    combined_key = combine_key_halves(key_half1, key_half2, shared_secret)
    
    assert len(combined_key) == 32

def test_combine_key_halves_real_values():
    """
    Test the combine_key_halves function with realistic inputs.

    Verifies that the combined key length is 32 bytes and matches the expected value derived using PBKDF2.
    """
    key_half1 = b'keyhalf1example__'
    key_half2 = b'keyhalf2example__'
    shared_secret = b'shared_secret_real'

    combined_key = combine_key_halves(key_half1, key_half2, shared_secret)

    assert len(combined_key) == 32

    expected_combined_key = PBKDF2(key_half1 + key_half2 + shared_secret, b'salt', dkLen=32, count=100000)
    assert combined_key == expected_combined_key

if __name__ == "__main__":
    pytest.main()
