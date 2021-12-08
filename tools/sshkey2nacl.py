#! /usr/bin/env python3

import sys
from libsigntools import C25519
from nacl.encoding import HexEncoder

def main():
    input_fn = sys.argv[1]
    output_fn = sys.argv[2]

    sk = C25519.signingKey(input_fn)
    with open('{}.sk'.format(output_fn), 'w') as f:
        f.write(sk.encode(HexEncoder).decode('ascii'))

    vk = C25519.verifyKey('{}.pub'.format(input_fn))
    with open('{}.vk'.format(output_fn), 'w') as f:
        f.write(vk.encode(HexEncoder).decode('ascii'))

if __name__ == '__main__':
  main()
