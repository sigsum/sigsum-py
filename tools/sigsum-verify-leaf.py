#! /usr/bin/env python3

# Input: vkeyfile shard_hint signature [checksum]
# Example: echo foo | ./sigsum-verify-leaf.py nacl.vk 0 $(echo foo | ./sigsum-sign-leaf.py nacl.sk 0)
# OK

import sys
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder
from libsigntools import checksum_stdin, ssh_to_sign

alg = 'sha256'

def main():
    keyfile = sys.argv[1]
    shard_hint = int(sys.argv[2])
    sig = bytes.fromhex(sys.argv[3])

    with open(keyfile, 'r') as f:
        vkey = VerifyKey(f.readline().strip(), encoder=HexEncoder)
    if len(sys.argv) > 4:
        checksum = bytes.fromhex(sys.argv[4])
    else:
        checksum = checksum_stdin(hashalg=alg)

    namespace = 'tree_leaf:v0:{}@sigsum.org'.format(shard_hint)
    data = ssh_to_sign(namespace, alg, checksum)
    vkey.verify(data, signature=sig)
    print("OK")

if __name__ == '__main__':
    main()
