import pytest

from .crypto import KeyfileError, KeyfileSigner

# Test data
KEY = "76C40BD07B59C06E573457B28BCD46A7D97B75777A23633AB9ECD52D5A551194"
MSG = b"Forty-two"
SIG = "7cf447e13341c926f33b5953174ae51ec9c8b846c253ff7f51f05691892ccd3e2157b6f201a66fda11b442b67c8ac3c684a2c248e06dbd4eb229a314bdda0905"


class TestKeyfileSigner:
    @pytest.fixture
    def key_path(self, tmp_path):
        return tmp_path / "key"

    def test_file_ok(self, tmp_path):
        file = tmp_path / "key"
        file.write_text(KEY + "\n")
        file.chmod(mode=0o700)
        signer = KeyfileSigner(file)
        assert signer.sign(MSG).hex() == SIG

    def test_file_notfound(self, tmp_path):
        file = tmp_path / "key"
        with pytest.raises(FileNotFoundError):
            KeyfileSigner(file)

    def test_directory(self, tmp_path):
        file = tmp_path / "key"
        file.mkdir()
        file.chmod(0o700)
        with pytest.raises(IsADirectoryError):
            KeyfileSigner(file)

    def test_file_invalid(self, tmp_path):
        file = tmp_path / "key"
        file.touch(mode=0o700)
        file.write_text("abcd")
        with pytest.raises(KeyfileError, match="Invalid key"):
            KeyfileSigner(file)

    def test_symlink(self, tmp_path):
        file = tmp_path / "thekey"
        file.write_text(KEY)
        file.chmod(mode=0o700)
        link = tmp_path / "key"
        link.symlink_to(file)
        sgnr = KeyfileSigner(link)
        assert sgnr.sign(MSG).hex() == SIG
