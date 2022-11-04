import io
import pathlib
import subprocess
import time

import pytest

from ._sshagent import Reader, SSHAgentError, SSHAgentProtocol, SSHAgentSigner, Writer

PUBKEY = "55963C66E74169AC5AF177B92C5583561C75FC8C3E3624AF020EC7C042CCB208"
MSG = b"Forty-two"
SIG = "7cf447e13341c926f33b5953174ae51ec9c8b846c253ff7f51f05691892ccd3e2157b6f201a66fda11b442b67c8ac3c684a2c248e06dbd4eb229a314bdda0905"


@pytest.fixture(scope="session")
def ssh_key():
    path = pathlib.Path(__file__).parent / "testdata" / "ssh-key"
    # Git doesn't track most permissions, so we make sure the file has the correct permission to be accepted by ssh-add on every run.
    path.chmod(0o600)
    return path


@pytest.fixture
def ssh_agent(tmp_path, ssh_key):
    sock = tmp_path / "ssh-agent.socket"
    proc = subprocess.Popen(["ssh-agent", "-D", "-a", str(sock)])
    time.sleep(1)
    subprocess.run(
        ["ssh-add", str(ssh_key)],
        check=True,
        env={"SSH_AUTH_SOCK": sock},
    )
    yield sock
    proc.kill()


class TestSSHAgentSigner:
    def test_no_socket(self):
        with pytest.raises(SSHAgentError, match="No such file or directory"):
            SSHAgentSigner(pathlib.Path("/does/not/exist"))

    def test_no_key(self, ssh_agent):
        subprocess.run(["ssh-add", "-D"], check=True, env={"SSH_AUTH_SOCK": ssh_agent})
        with pytest.raises(
            SSHAgentError, match="ssh-agent should have exactly one ed25519 key"
        ):
            SSHAgentSigner(ssh_agent)

    def test_public(self, ssh_agent):
        signer = SSHAgentSigner(ssh_agent)
        assert signer.public().hex().upper() == PUBKEY

    def test_sign(self, ssh_agent):
        signer = SSHAgentSigner(ssh_agent)
        assert signer.sign(MSG).hex() == SIG


class FakeSocket:
    def __init__(self, expected: str, response: str):
        self.expected = bytes.fromhex(expected) if expected else None
        self.actual = b""
        self.response = io.BytesIO(bytes.fromhex(response))

    def send(self, b: bytes):
        self.actual += b

    def recv(self, size: int) -> bytes:
        if self.expected is not None:
            assert self.actual.hex() == self.expected.hex()
        return self.response.read(size)


class TestSSHAgentProtocol:
    def test_request_identities(self, tmp_path):
        sock = FakeSocket(
            expected="00000001 0b",
            response="0000007b 0c"
            "00000002"
            "00000033 0000000b 7373682d65643235353139 00000020 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 00000000"
            "00000033 0000000b 7373682d65643235353139 00000020 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 00000000",
        )
        proto = SSHAgentProtocol(sock)
        identities = proto.request_identities()
        assert identities == [b"\xaa" * 32, b"\xbb" * 32]

    @pytest.mark.parametrize(
        "response,match",
        [
            ("00000001 05", "ssh-agent failure"),
            ("00000001 ff", "unexpected message type: 255"),
            (
                "00000018 0c 00000001 0000000f 00000003 787878 00000000 00000000",
                "unknown key type: b'xxx'",
            ),
        ],
    )
    def test_request_identities_error(self, tmp_path, response, match):
        sock = FakeSocket(None, response)
        proto = SSHAgentProtocol(sock)
        with pytest.raises(SSHAgentError, match=match):
            proto.request_identities()

    def test_sign_request(self, tmp_path):
        sock = FakeSocket(
            expected="00000044 0d"
            "00000033 0000000b 7373682d65643235353139 00000020 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "00000004 deadbeef"
            "00000000",
            response="00000058 0e"
            "00000053 0000000b 7373682d65643235353139 00000040"
            "de8a33400b8c85b71d68451e0924978823bbeb5c67f8aa4386bb0e0e1373ed0e"
            "b3134de24e582a36a958ab32568c54a4bc8b82203afcfd19399f34486730d307",
        )
        proto = SSHAgentProtocol(sock)
        msg = bytes.fromhex("deadbeef")
        sig = proto.sign_request(b"\xaa" * 32, msg, 0)
        assert sig == bytes.fromhex(
            "de8a33400b8c85b71d68451e0924978823bbeb5c67f8aa4386bb0e0e1373ed0e"
            "b3134de24e582a36a958ab32568c54a4bc8b82203afcfd19399f34486730d307"
        )

    @pytest.mark.parametrize(
        "response,match",
        [
            ("00000001 05", "ssh-agent failure"),
            ("00000001 ff", "unexpected message type: 255"),
        ],
    )
    def test_sign_request_error(self, tmp_path, response, match):
        sock = FakeSocket(None, response)
        proto = SSHAgentProtocol(sock)
        msg = bytes.fromhex("deadbeef")
        with pytest.raises(SSHAgentError, match=match):
            proto.sign_request(b"\xaa" * 32, msg, 0)


class TestReader:
    def test_take(self):
        r = Reader(b"foobar")
        assert r.take(3) == b"foo"
        assert r.take(3) == b"bar"
        with pytest.raises(EOFError):
            r.take(1)

    def test_read_byte(self):
        r = Reader(b"\x42")
        assert r.read_byte() == 0x42

    def test_read_uint32(self):
        r = Reader(b"\x00\x00\x00\x2a")
        assert r.read_uint32() == 42

    def test_read_string(self):
        r = Reader(b"\x00\x00\x00\x07ssh-foo")
        assert r.read_string() == b"ssh-foo"


class TestWriter:
    def test_write_byte(self):
        w = Writer()
        w.write_byte(0x42)
        assert w.getvalue() == b"\x42"

    def test_write_uint32(self):
        w = Writer()
        w.write_uint32(42)
        assert w.getvalue() == b"\x00\x00\x00\x2a"

    def test_write_string(self):
        w = Writer()
        w.write_string(b"ssh-foo")
        assert w.getvalue() == b"\x00\x00\x00\x07ssh-foo"
