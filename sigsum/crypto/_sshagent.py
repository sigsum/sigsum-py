import io
import pathlib
import socket
import struct
import typing

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5


class SSHAgentSigner:
    def __init__(self, sock: pathlib.Path):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.connect(str(sock))
        except FileNotFoundError as e:
            raise SSHAgentError(f"Error connecting to ssh-agent: {e}") from e
        self.__proto = SSHAgentProtocol(conn)
        keys = self.__proto.request_identities()
        if len(keys) != 1:
            raise SSHAgentError("ssh-agent should have exactly one ed25519 key")
        self.__key = keys[0]

    def public(self) -> bytes:
        return self.__key

    def sign(self, msg: bytes) -> bytes:
        return self.__proto.sign_request(self.__key, msg, 0)


class SSHAgentError(Exception):
    pass


class SSHAgentProtocol:
    class Conn(typing.Protocol):
        def send(self, b: bytes):
            pass

        def recv(self, size: int) -> bytes:
            pass

    def __init__(self, conn: Conn):
        self.__conn = conn

    def request_identities(self) -> typing.List[bytes]:
        req = Writer()
        req.write_byte(SSH_AGENTC_REQUEST_IDENTITIES)
        self._send(req.getvalue())
        resp = Reader(self._recv())
        resptype = resp.read_byte()
        if resptype == SSH_AGENT_FAILURE:
            raise SSHAgentError("ssh-agent failure")
        if resptype != SSH_AGENT_IDENTITIES_ANSWER:
            raise SSHAgentError(f"unexpected message type: {resptype}")
        nkeys = resp.read_uint32()
        result = []
        for i in range(nkeys):
            blob = Reader(resp.read_string())
            keytype = blob.read_string()
            if keytype != b"ssh-ed25519":
                raise SSHAgentError(f"unknown key type: {keytype!r}")
            key = blob.read_string()
            resp.read_string()  # Ignoring comment
            result.append(key)
        return result

    def sign_request(self, key: bytes, data: bytes, flags: int) -> bytes:
        req = Writer()
        req.write_byte(SSH_AGENTC_SIGN_REQUEST)
        blob = Writer()
        blob.write_string(b"ssh-ed25519")
        blob.write_string(key)
        req.write_string(blob.getvalue())
        req.write_string(data)
        req.write_uint32(flags)
        self._send(req.getvalue())
        resp = Reader(self._recv())
        resptype = resp.read_byte()
        if resptype == SSH_AGENT_FAILURE:
            raise SSHAgentError("ssh-agent failure")
        if resptype != SSH_AGENT_SIGN_RESPONSE:
            raise SSHAgentError(f"unexpected message type: {resptype}")
        sig = Reader(resp.read_string())
        assert sig.read_string() == b"ssh-ed25519"
        return sig.read_string()

    def _send(self, msg: bytes):
        self.__conn.send(struct.pack("!I", len(msg)))
        self.__conn.send(msg)

    def _recv(self) -> bytes:
        (msglen,) = struct.unpack("!I", self.__conn.recv(4))
        msg = self.__conn.recv(msglen)
        assert len(msg) == msglen
        return msg


class Reader:
    def __init__(self, input: bytes):
        self.__inner = io.BytesIO(input)

    def take(self, n: int) -> bytes:
        result = self.__inner.read(n)
        if len(result) < n:
            raise EOFError(f"need at least {n-len(result)} more bytes")
        return result

    def read_byte(self) -> int:
        return self.take(1)[0]

    def read_uint32(self) -> int:
        return struct.unpack("!I", self.take(4))[0]

    def read_string(self) -> bytes:
        return self.take(self.read_uint32())


class Writer:
    def __init__(self):
        self.__inner = io.BytesIO()

    def getvalue(self) -> bytes:
        return self.__inner.getvalue()

    def write_byte(self, v: int):
        self.__inner.write(struct.pack("B", v))

    def write_uint32(self, v: int):
        self.__inner.write(struct.pack("!I", v))

    def write_string(self, v: bytes):
        self.write_uint32(len(v))
        self.__inner.write(v)
