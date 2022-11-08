import struct
from hashlib import sha256

import nacl.exceptions
from tools.libsigntools import ssh_to_sign

from . import ascii

class TreeHead:
    def __init__(self, sth_data):
        lines = sth_data.splitlines()
        assert(len(lines) == 4)

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

    def text(self):
        return ascii.dumps([("timestamp", self.timestamp),
                            ("tree_size", self.tree_size),
                            ("root_hash", self.root_hash),
                            ("signature", self.signature)]).encode('ascii')

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
