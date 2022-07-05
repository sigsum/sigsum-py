import importlib

import pytest

witness = importlib.import_module("sigsum-witness")  # To import a module with a '-'


class Test_check_sigkeyfile:
    def test_file_ok(self, tmp_path):
        path = tmp_path / "key"
        path.touch(mode=0o700)
        assert witness.check_sigkeyfile(path) is None

    def test_file_notfound(self, tmp_path):
        path = tmp_path / "key"
        with pytest.raises(
            witness.SigKeyFileError,
            match=f"ERROR: File not found: {path}",
        ):
            witness.check_sigkeyfile(path)

    def test_notafile(self, tmp_path):
        path = tmp_path / "key"
        path.mkdir()
        with pytest.raises(
            witness.SigKeyFileError,
            match=f"ERROR: Signing key file {path} must be a regular file",
        ):
            witness.check_sigkeyfile(path)

    def test_file_badmode(self, tmp_path):
        path = tmp_path / "key"
        path.touch(mode=0o755)
        with pytest.raises(
            witness.SigKeyFileError,
            match=f"ERROR: Signing key file {path} permissions too lax: 0755",
        ):
            witness.check_sigkeyfile(path)

    def test_symlink_ok(self, tmp_path):
        filepath = tmp_path / "thekey"
        filepath.touch(mode=0o700)
        linkpath = tmp_path / "key"
        linkpath.symlink_to(filepath)
        assert witness.check_sigkeyfile(linkpath) is None

    def test_symlink_badmode(self, tmp_path):
        filepath = tmp_path / "thekey"
        filepath.touch(mode=0o755)
        linkpath = tmp_path / "key"
        linkpath.symlink_to(filepath)
        with pytest.raises(
            witness.SigKeyFileError,
            match=f"ERROR: Signing key file {linkpath} permissions too lax: 0755",
        ):
            witness.check_sigkeyfile(linkpath)

    def test_symlink_dangling(self, tmp_path):
        filepath = tmp_path / "thekey"
        linkpath = tmp_path / "key"
        linkpath.symlink_to(filepath)
        with pytest.raises(
            witness.SigKeyFileError,
            match=f"ERROR: File not found: {linkpath}",
        ):
            witness.check_sigkeyfile(linkpath)
