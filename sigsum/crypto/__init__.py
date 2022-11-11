import typing

from ._keyfile import KeyfileError, KeyfileSigner
from ._sshagent import SSHAgentError, SSHAgentSigner


class Signer(typing.Protocol):
    def sign(self, msg: bytes) -> bytes:
        pass

    def public(self) -> bytes:
        pass
