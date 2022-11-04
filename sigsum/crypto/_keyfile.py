import pathlib

import nacl.encoding
import nacl.signing


class KeyfileError(Exception):
    pass


class KeyfileSigner:
    def __init__(self, p: pathlib.Path):
        b = p.read_bytes().strip()
        try:
            self.__sk = nacl.signing.SigningKey(b, nacl.encoding.HexEncoder)
        except nacl.exceptions.ValueError as e:
            raise KeyfileError(f"Invalid key: {e}") from e

    def sign(self, msg: bytes) -> bytes:
        """sign signs the given message."""
        return self.__sk.sign(msg).signature

    def public(self) -> bytes:
        return self.__sk.verify_key.encode()
