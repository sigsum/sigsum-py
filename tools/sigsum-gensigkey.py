#! /usr/bin/env python3

import sys
import os
from stat import *
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

def generate_and_store_sigkey(fn):
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    with open(fn, 'w') as f:
        os.chmod(f.fileno(), S_IRUSR)
        f.write(signing_key.encode(HexEncoder).decode('ascii') + '\n')
    print(verify_key.encode(HexEncoder).decode('ascii'))

def main():
    generate_and_store_sigkey(sys.argv[1])

if __name__ == '__main__':
    main()
