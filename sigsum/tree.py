import struct
from dataclasses import dataclass
from hashlib import sha256

import nacl.exceptions
from tools.libsigntools import ssh_to_sign

from . import ascii

class TreeHead:
    def __init__(self, sth_data):
        lines = sth_data.splitlines()
        if len(lines) != 4:
            raise ascii.ASCIIDecodeError(
                "Expecting four lines for a signed tree head, got "
                + str(len(lines)))
        self.__timestamp = ascii.parse_int(lines[0], "timestamp")
        self.__tree_size = ascii.parse_int(lines[1], "tree_size")
        self.__root_hash = ascii.parse_hash(lines[2], "root_hash")
        self.__signature = ascii.parse_signature(lines[3], "signature")

    @property
    def timestamp(self):
        return self.__timestamp

    @property
    def tree_size(self):
        return self.__tree_size

    @property
    def root_hash(self):
        return self.__root_hash

    @property
    def signature(self):
        return self.__signature

    def text(self):
        return ascii.dumps([("timestamp", self.__timestamp),
                            ("tree_size", self.__tree_size),
                            ("root_hash", self.__root_hash),
                            ("signature", self.__signature)]).encode('ascii')

    def to_signed_data(self, pubkey):
        namespace = "tree-head:v0@sigsum.org"
        msg = struct.pack("!QQ", self.timestamp, self.tree_size)
        msg += self.root_hash
        msg += sha256(pubkey.encode()).digest()
        assert(len(msg) == 8 + 8 + 32 + 32)
        return ssh_to_sign(namespace, 'sha256', sha256(msg).digest())

    def signature_valid(self, pubkey):
        data = self.to_signed_data(pubkey)
        try:
            verified_data = pubkey.verify(self.__signature + data)
        except nacl.exceptions.BadSignatureError:
            return False
        assert(verified_data == data)
        return True


class ConsistencyProof:
    def __init__(self, old_size, new_size, consistency_proof_data):
        self.__old_size = old_size
        self.__new_size = new_size
        self.__path = []
        for line in consistency_proof_data.splitlines():
            self.__path.append(ascii.parse_hash(line, "consistency_path"))

    def old_size(self):
        return self.__old_size
    def new_size(self):
        return self.__new_size

    def path(self):
        return self.__path


@dataclass(frozen=True)
class Cosignature:
    keyhash: bytes
    signature: bytes

    def text(self):
        return ascii.dumps(
            [("cosignature", f"{self.keyhash.hex()} {self.signature.hex()}")]
        ).encode("ascii")
