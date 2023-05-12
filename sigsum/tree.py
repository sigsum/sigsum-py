import struct
import typing
from dataclasses import dataclass
from hashlib import sha256

import nacl.exceptions
from tools.libsigntools import ssh_to_sign

from . import ascii


@dataclass
class TreeHead:
    size: int
    root_hash: bytes
    signature: bytes

    @staticmethod
    def fromascii(data: str) -> "TreeHead":
        lines = data.splitlines()
        if len(lines) != 3:
            raise ascii.ASCIIDecodeError(
                "Expecting 3 lines for a signed tree head, got " + str(len(lines))
            )
        size = ascii.parse_int(lines[0], "size")
        root_hash = ascii.parse_hash(lines[1], "root_hash")
        signature = ascii.parse_signature(lines[2], "signature")
        return TreeHead(size, root_hash, signature)

    def ascii(self) -> bytes:
        return ascii.dumps(
            [
                ("size", self.size),
                ("root_hash", self.root_hash),
                ("signature", self.signature),
            ]
        ).encode("ascii")

    def to_signed_data(self) -> bytes:
        namespace = "signed-tree-head:v0@sigsum.org"
        msg = struct.pack("!Q", self.size)
        msg += self.root_hash
        assert len(msg) == 8 + 32
        return ssh_to_sign(namespace, "sha256", sha256(msg).digest())

    def signature_valid(self, pubkey) -> bool:
        data = self.to_signed_data()
        try:
            verified_data = pubkey.verify(self.signature + data)
        except nacl.exceptions.BadSignatureError:
            return False
        assert verified_data == data
        return True

    def to_cosigned_data(self, timestamp : int, log_key_hash : bytes) -> bytes:
        namespace = "cosigned-tree-head:v0@sigsum.org"
        msg = struct.pack("!Q", self.size)
        msg += self.root_hash
        msg += log_key_hash
        msg += struct.pack("!Q", timestamp)
        assert len(msg) == 80
        return ssh_to_sign(namespace, "sha256", sha256(msg).digest())

@dataclass(frozen=True)
class ConsistencyProof:
    old_size: int
    new_size: int
    path: typing.Sequence[bytes]

    @staticmethod
    def fromascii(old_size, new_size, data: str) -> "ConsistencyProof":
        path = []
        for line in data.splitlines():
            path.append(ascii.parse_hash(line, "node_hash"))
        return ConsistencyProof(old_size, new_size, path)


@dataclass(frozen=True)
class Cosignature:
    keyhash: bytes
    timestamp: int
    signature: bytes

    def ascii(self):
        return ascii.dumps(
            [("cosignature", f"{self.keyhash.hex()} {self.timestamp} {self.signature.hex()}")]
        ).encode("ascii")
