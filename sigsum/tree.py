import struct
import typing
from dataclasses import dataclass
from hashlib import sha256
from base64 import b64encode

import nacl.exceptions

from . import ascii


@dataclass
class TreeHead:
    size: int
    root_hash: bytes
    signature: bytes

    @staticmethod
    def fromascii(data: str) -> "TreeHead":
        return TreeHead.from_lines(data.splitlines())

    @staticmethod
    def from_lines(lines: typing.List[str]) -> "TreeHead":
        if len(lines) != 3:
            raise ascii.ASCIIDecodeError(
                "Expecting 3 lines for a signed tree head, got " + str(len(lines))
            )
        size = ascii.parse_int(lines[0], "size")
        root_hash = ascii.parse_hash(lines[1], "root_hash")
        signature = ascii.parse_signature(lines[2], "signature")
        return TreeHead(size, root_hash, signature)

    # Return an empty tree, without signature
    @staticmethod
    def make_empty() -> "TreeHead":
        return TreeHead(0, sha256(b"").digest(), b"")

    def ascii(self) -> bytes:
        return ascii.dumps(
            [
                ("size", self.size),
                ("root_hash", self.root_hash),
                ("signature", self.signature),
            ]
        ).encode("ascii")

    def to_signed_data(self, key_hash : bytes) -> bytes:
        return (f"sigsum.org/v1/tree/{key_hash.hex()}\n{self.size}\n".encode("ascii")
                + b64encode(self.root_hash) + b"\n")

    def signature_valid(self, pubkey):
        data = self.to_signed_data(sha256(pubkey.encode()).digest())
        try:
            verified_data = pubkey.verify(self.signature + data)
        except nacl.exceptions.BadSignatureError:
            return False
        assert verified_data == data
        return True

    def to_cosigned_data(self, log_key_hash: bytes, timestamp: int) -> bytes:
        namespace = "cosignature/v1"
        return ("{}\ntime {}\n".format(namespace, timestamp).encode("ascii")
                + self.to_signed_data(log_key_hash))

@dataclass(frozen=True)
class ConsistencyProof:
    path: typing.List[bytes]

    @staticmethod
    def fromascii(data: str) -> "ConsistencyProof":
        return ConsistencyProof.from_lines(data.splitlines())

    @staticmethod
    def from_lines(lines: typing.List[str]) -> "ConsistencyProof":
        path = []
        for line in lines:
            path.append(ascii.parse_hash(line, "node_hash"))
        return ConsistencyProof(path)

    def proof_valid(self, first : TreeHead, second : TreeHead) -> bool:
        # First handle trivial cases with empty path.
        if first.size == second.size:
            return len(self.path) == 0 and first.root_hash == second.root_hash

        if first.size == 0:
            return len(self.path) == 0

        assert first.size < second.size
        # Implements the algorithm for consistency proof verification outlined
        # in RFC6962-BIS, see
        # https://datatracker.ietf.org/doc/html/draft-ietf-trans-rfc6962-bis-39#section-2.1.4.2
        if len(self.path) == 0:
            return False

        path = self.path
        # If first size is an exact power of two, prepend first root_hash to the path.
        assert first.size > 0
        if first.size & (first.size - 1) == 0:
            path = [first.root_hash] + path

        fn = first.size - 1
        sn = second.size - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1

        fr = path[0]
        sr = path[0]

        for c in path[1:]:
            if sn == 0:
                return False

            if fn & 1 or fn == sn:
                fr = sha256(b'\x01' + c + fr).digest()
                sr = sha256(b'\x01' + c + sr).digest()
                while fn != 0 and fn & 1 == 0:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = sha256(b'\x01' + sr + c).digest()

            fn >>= 1
            sn >>= 1

        return sn == 0 and fr == first.root_hash and sr == second.root_hash

@dataclass(frozen=True)
class Cosignature:
    keyhash: bytes
    timestamp: int
    signature: bytes

    def ascii(self):
        return ascii.dumps(
            [("cosignature", f"v1 {self.keyhash.hex()} {self.timestamp} {self.signature.hex()}")]
        ).encode("ascii")

@dataclass(frozen=True)
class AddTreeHeadRequest:
    key_hash: bytes
    tree_head: TreeHead
    old_size: int
    proof: ConsistencyProof

    @staticmethod
    def fromascii(data: str) -> "AddTreeHeadRequest":
        lines = data.splitlines()
        if len(lines) < 5:
            raise ascii.ASCIIDecodeError(
                f"Expecting >= 5 lines for an add tree head request, got {len(lines)}"
            )
        key_hash = ascii.parse_hash(lines[0], "key_hash")
        tree_head = TreeHead.from_lines(lines[1:4])
        old_size = ascii.parse_int(lines[4], "old_size")
        proof = ConsistencyProof.from_lines(lines[5:])
        if old_size > tree_head.size:
            raise ascii.ASCIIDecodeError("invalid, old_size ({}) > size ({})".format(old_size, tree_head.size))
        return AddTreeHeadRequest(key_hash, tree_head, old_size, proof)
