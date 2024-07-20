import pytest
from shadowmessenger.master import FileKeyStorage

@pytest.fixture
def key_storage(tmp_path):
    return FileKeyStorage(path=str(tmp_path / "test_key.key"))

def test_save_load_key(key_storage):
    key = b"testkey1234567890"
    key_storage.save_key(key)
    loaded_key = key_storage.load_key()
    assert loaded_key == key
