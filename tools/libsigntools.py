import sys
import struct
from hashlib import sha256, sha512

def checksum_stdin(hashalg='sha256'):
    if hashalg == 'sha256':
        d = sha256()
    elif hashalg == 'sha512':
        d = sha512()
    else:
        return None

    while True:
        buf = sys.stdin.buffer.read()
        if not buf:
            break
        d.update(buf)

    return d.digest()

def ssh_to_sign(namespace, hashalg, checksum):
    if hashalg == 'sha256':
        hashlen = 32
    elif hashalg == 'sha512':
        hashlen = 64
    else:
        return None
    s = struct.pack('!6sI{}sII6sI{}s'.format(len(namespace), hashlen),
                    b'SSHSIG',
                    len(namespace), bytes(namespace, 'ascii'),
                    0,
                    6, bytes(hashalg, 'ascii'),
                    hashlen, checksum)
    return s

# Adapted from https://stackoverflow.com/questions/65684414/how-to-use-ssh-keygen-ed25519-keys-for-encryption-in-python
# Author: LJHW
from base64 import b64decode
from nacl.encoding import RawEncoder
from nacl.signing  import SigningKey, VerifyKey
class C25519:
    # Adapted from https://gist.github.com/R-VdP/b7ac0106a4fd395ee1c37bfe6f552a36 sealing.py
    # Author: Ramses https://github.com/R-VdP
    __key_length = 32
    __private_key_signature = b'\x00\x00\x00\x40'
    __public_key_signature  = b'\x00\x00\x00\x20'

    @classmethod
    def __bytes_after(cls, signature, length, bytestr):
        start = bytestr.find(signature) + len(signature)
        return bytestr[start:start+length]

    @classmethod
    def __extract_signing_key(cls, private_data):
        openssh_bytes = b64decode(private_data)
        private_bytes = cls.__bytes_after(
            cls.__private_key_signature,
            cls.__key_length,
            openssh_bytes
        )
        signing_key = SigningKey(seed=private_bytes, encoder=RawEncoder)
        return signing_key

    @classmethod
    def __extract_verify_key(cls, public_data):
        openssh_bytes = b64decode(public_data)
        public_bytes = cls.__bytes_after(
            cls.__public_key_signature,
            cls.__key_length,
            openssh_bytes
        )
        verify_key = VerifyKey(key=public_bytes, encoder=RawEncoder)
        return verify_key

    @classmethod
    def __private_data_from_file(cls, file_name):
        with open(file_name, 'r') as file:
            contents = file.read()
        contents = contents.split('\n')
        private_data = ''
        for line in contents:
            if 'PRIVATE KEY' in line:
                continue
            if not line:
                continue
            private_data += line
        return private_data

    @classmethod
    def __public_data_from_file(cls, file_name):
        with open(file_name, 'r') as file:
            contents = file.read()
        contents = contents.split(' ')
        # assert contents[0] == 'ssh-ed25519'
        public_data = contents[1].strip(' ')
        return public_data

    @classmethod
    def signingKey(cls, private_ed25519_file):
        private_data = cls.__private_data_from_file(private_ed25519_file)
        signing_key = cls.__extract_signing_key(private_data)
        return signing_key

    @classmethod
    def verifyKey(cls, public_ed25519_file):
        public_data = cls.__public_data_from_file(public_ed25519_file)
        verify_key = cls.__extract_verify_key(public_data)
        return verify_key

    @classmethod
    def privateKey(cls, private_ed25519_file):
        signing_key = cls.signingKey(private_ed25519_file)
        return signing_key.to_curve25519_private_key()

    @classmethod
    def publicKey(cls, public_ed25519_file):
        verify_key = cls.verifyKey(public_ed25519_file)
        return verify_key.to_curve25519_public_key()
