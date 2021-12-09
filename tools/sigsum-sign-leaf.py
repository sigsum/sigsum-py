#! /usr/bin/env python3

# Input: skeyfile shard_hint [checksum]
# Output: tree_leaf signature
# Example: echo foo | ./sigsum-sign-leaf.py nacl.sk 1633039200
# be70f92465c27bf412008f26fa953d06899c53fa9867f40d9c0a1d657b188c9631699954728c719cf6b3819c1343c6e9e454cd9d519a9bf96dad3cf4cd959c0a

import struct, sys, binascii
from base64 import b64encode
from nacl.signing import VerifyKey, SigningKey
from nacl.encoding import HexEncoder
from libsigntools import checksum_stdin, ssh_to_sign

alg = 'sha512'

def ssh_blob(vk, sig, namespace):
    vkdata = struct.pack('!I11sI32s',
                         11, bytes('ssh-ed25519', 'ascii'),
                         32, vk.encode())
    assert(len(vkdata) == 51)

    assert(len(sig) == 64)
    sigdata = struct.pack('!I11sI64s',
                          11, bytes('ssh-ed25519', 'ascii'),
                          64, sig)
    assert(len(sigdata) == 83)

    s = "-----BEGIN SSH SIGNATURE-----\n"
    b = b64encode(struct.pack('!6sII51sI{}sII6sI83s'.format(len(namespace)),
                              b'SSHSIG',
                              1,
                              51, vkdata,
                              len(namespace), bytes(namespace, 'ascii'),
                              0,
                              6, bytes(alg, 'ascii'),
                              83, sigdata)).decode('ascii')
    while len(b) > 0:
        s += b[:70] + '\n'
        b = b[70:]
    s += "-----END SSH SIGNATURE-----\n"
    return s

def main():
    keyfile = sys.argv[1]
    shard_hint = int(sys.argv[2])
    if len(sys.argv) > 3:
        checksum = bytes.fromhex(sys.argv[3])
    else:
        checksum = checksum_stdin(hashalg=alg)

    with open(keyfile, 'r') as f:
        signing_key = SigningKey(f.readline().strip(), encoder=HexEncoder)
    namespace = 'tree_leaf:v0:{}@sigsum.org'.format(shard_hint)
    signature = signing_key.sign(ssh_to_sign(namespace, alg, checksum)).signature

    print(binascii.hexlify(signature).decode('ascii'))
    if False:
        print(ssh_blob(signing_key.verify_key, signature, namespace))

if __name__ == '__main__':
    main()
