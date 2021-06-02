#! /usr/bin/env python3

# Sign the most recently published tree head from a given ST log,
# after verifying a consistency proof from an already verified tree
# head to this new tree head.

# A verified tree head is expected to be found in the file
# ~/.config/siglog-witness/signed_tree_head . It's updated once a
# newer tree head has been verified successfully.

# If the config file ~/.config/siglog-witness/siglog-witness.conf
# exists and is readable, options are read from it. Options read from
# the config file can be overridden on the command line.

import sys
import os
from stat import *
import argparse
import requests
import struct
from binascii import hexlify, unhexlify
import nacl.encoding
import nacl.signing
from hashlib import sha256

# TODO maybe stop mixing dashes and underscores in directory names and filenames

BASE_URL_DEFAULT = 'http://tlog-poc.system-transparency.org:6965/'
CONFIG_DIR_DEFAULT = os.path.expanduser('~/.config/siglog-witness/')
SIGKEY_FILE_DEFAULT = CONFIG_DIR_DEFAULT + 'signing_key'

CONFIG_FILE = CONFIG_DIR_DEFAULT + 'siglog-witness.conf'

class Parser:
    def __init__(self):
        p = argparse.ArgumentParser(
            description='Sign the most recently published tree head from a given siglog, after verifying it against an older tree.')

        p.add_argument('-b', '--bootstrap-log',
                       action='store_true',
                       help="Sign and save fetched tree head without verifying a consistency proof against a previous tree head. NOTE: User intervention required.")

        p.add_argument('-d', '--base-dir',
                       default=CONFIG_DIR_DEFAULT,
                       help="Configuration directory ({})".format(CONFIG_DIR_DEFAULT))

        p.add_argument('-l', '--log-verification-key',
                       help="Log verification key")

        p.add_argument('--save-config',
                       action='store_true',
                       help="Save command line options to the configuration file")

        p.add_argument('-s', '--sigkey-file',
                       default=SIGKEY_FILE_DEFAULT,
                       help="Signing key file ({})".format(SIGKEY_FILE_DEFAULT))

        p.add_argument('-u', '--base-url',
                       default=BASE_URL_DEFAULT,
                       help="Log base URL ({})".format(BASE_URL_DEFAULT))

        self.parser = p

def parse_config(filename):
    try:
        lines = []
        with open(filename, 'r') as f:
            line = f.readline()
            while line:
                lines.append(line.strip())
                line = f.readline()
            g_args.parser.parse_args(lines, namespace=g_args)
    except FileNotFoundError:
        pass

def parse_args(argv):
    g_args.parser.parse_args(namespace=g_args)

def parse_keyval(text):
    dictx = {}
    for line in text.split():
        (key, val) = line.split('=')
        if not key in dictx:
            dictx[key] = val
        else:
            if type(dictx[key]) is list:
                dictx[key] += [val]
            else:
                dictx[key] = [dictx[key], val]
    return dictx

class TreeHead:
    def __init__(self, sth_data):
        self._text = parse_keyval(sth_data)
        assert(len(self._text) == 5)
        assert('timestamp' in self._text)
        assert('tree_size' in self._text)
        assert('root_hash' in self._text)
        assert('signature' in self._text)
        assert('key_hash' in self._text)

    def text(self):
        text = 'timestamp={}\n'.format(self._text['timestamp'])
        text += 'tree_size={}\n'.format(self._text['tree_size'])
        text += 'root_hash={}\n'.format(self._text['root_hash'])
        text += 'signature={}\n'.format(self._text['signature'])
        text += 'key_hash={}\n'.format(self._text['key_hash'])
        return text.encode('ascii')

    def serialise(self):
        data = struct.pack('!QQ', self.timestamp(), self.tree_size())
        data += unhexlify(self._text['root_hash'])
        assert(len(data) == 48)
        return data

    def signature_valid(self, pubkey):
        # Guard against tree head with >1 signature -- don't try to
        # validate a cosigned tree head.
        assert(type(self._text['signature']) is str)
        sig = unhexlify(self._text['signature'])
        assert(len(sig) == 64)
        data = self.serialise()
        try:
            verified_data = pubkey.verify(sig + data)
        except nacl.exceptions.BadSignatureError:
            return False
        assert(verified_data == data)
        return True

    def timestamp(self):
        return int(self._text['timestamp'])
    def tree_size(self):
        return int(self._text['tree_size'])
    def root_hash(self):
        return unhexlify(self._text['root_hash'])

class ConsistencyProof():
    def __init__(self, consistency_proof_data):
        self._text = parse_keyval(consistency_proof_data)
        assert(len(self._text) == 3)
        assert('old_size' in self._text)
        assert('new_size' in self._text)
        assert('consistency_path' in self._text)

    def old_size(self):
        return int(self._text['old_size'])
    def new_size(self):
        return int(self._text['new_size'])
    def path(self):
        if type(self._text['consistency_path']) is list:
            return [unhexlify(e) for e in self._text['consistency_path']]
        else:
            return [unhexlify(self._text['consistency_path'])]

def read_tree_head():
    filename = os.path.expanduser(g_args.base_dir) + 'signed_tree_head'
    try:
        with open(filename, mode='r') as f:
            return TreeHead(f.read())
    except FileNotFoundError:
        return None

def store_tree_head(tree_head):
    dirname = os.path.expanduser(g_args.base_dir)
    try:
        os.stat(dirname)
    except FileNotFoundError:
        os.makedirs(dirname)
    with open(dirname + 'signed_tree_head', mode='w+b') as f:
        f.write(tree_head.text())

def fetch_tree_head():
    req = requests.get(g_args.base_url + 'st/v0/get-tree-head-to-sign')
    if req.status_code != 200:
        return None
    return TreeHead(req.content.decode())

def fetch_consistency_proof(first, second):
    post_data = 'old_size={}\n'.format(first)
    post_data += 'new_size={}\n'.format(second)
    req = requests.post(g_args.base_url + 'st/v0/get-consistency-proof', post_data)
    if req.status_code != 200:
        print("ERROR: st/v0/get-consistency-proof({}) => {}".format(post_data, req))
        return None
    return ConsistencyProof(req.content.decode())

def numbits(n):
    p = 0
    while n > 0:
        if n & 1:
            p += 1
        n >>= 1
    return p

# Implements the algorithm for consistency proof verification outlined
# in RFC6962-BIS, see
# https://datatracker.ietf.org/doc/html/draft-ietf-trans-rfc6962-bis-39#section-2.1.4.2
def consistency_proof_valid(first, second, proof):
    assert(first.tree_size() == proof.old_size())
    assert(second.tree_size() == proof.new_size())

    path = proof.path()
    if len(path) == 0:
        return False
    if numbits(first.tree_size()) == 1:
        path = [first.root_hash()] + path

    fn = first.tree_size() - 1
    sn = second.tree_size() - 1
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

    return sn == 0 and fr == first.root_hash() and sr == second.root_hash()

def send_to_log(keyhash_hex, signature_hex):
    post_data = 'signature={}\n'.format(signature_hex)
    post_data += 'key_hash={}\n'.format(keyhash_hex)
    req = requests.post(g_args.base_url + 'st/v0/add-cosignature', post_data)
    if req.status_code != 200:
        return req

def sign_and_send_sig(signing_key, sth):
    keyhash = sha256(signing_key.verify_key.encode()).hexdigest()
    status = send_to_log(keyhash,
                         hexlify(signing_key.sign(sth.serialise()).signature).decode('ascii'))
    if status:
        print("ERROR: Unable to post signature to log: {} => {}: {}".format(status.url,
                                                                            status.status_code,
                                                                            status.text))
def main(args):
    global g_args
    g_args = Parser()
    parse_config(CONFIG_FILE)
    parse_args(args)
    if g_args.save_config:
        # TODO write config file
        print("ERROR: --save-config is not yet implemented")
        return 12

    consistency_verified = False
    ignore_consistency = False

    # TODO stop returning random integers -- use 1 all over or do something clever

    if not g_args.log_verification_key:
        print("ERROR: missing log verification key")
        return 7
    try:
        log_verification_key = nacl.signing.VerifyKey(g_args.log_verification_key, encoder=nacl.encoding.HexEncoder)
    except:
        print("ERROR: invalid log verification key: {}".format(g_args.log_verification_key))
        return 8

    try:
        s = os.stat(g_args.sigkey_file, follow_symlinks=False)
        if not S_ISREG(s.st_mode):
            print("ERROR: Signing key file {} must be a regular file".format(g_args.sigkey_file))
            return 9
        if S_IMODE(s.st_mode) & 0o077 != 0:
            print("ERROR: Signing key file {} permissions too lax: {:04o}".format(g_args.sigkey_file, S_IMODE(s.st_mode)))
            return 10
    except FileNotFoundError:
        print("INFO: Signing key file {} not found -- generating new signing key".format(g_args.sigkey_file))
        signing_key = nacl.signing.SigningKey.generate()
        print("INFO: verification key: {}".format(signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)))
        with open(g_args.sigkey_file, 'w') as f:
            os.chmod(f.fileno(), S_IRUSR)
            f.write(signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('ascii'))

    with open(g_args.sigkey_file, 'r') as f:
        try:
            signing_key = nacl.signing.SigningKey(f.readline().strip(), encoder=nacl.encoding.HexEncoder)
        except:
            print("ERROR: Invalid signing key in {}".format(g_args.sigkey_file))
            return 11

    new = fetch_tree_head()
    if not new:
        print("ERROR: unable to fetch new tree head")
        return 6
    if not new.signature_valid(log_verification_key):
        print("ERROR: signature of new tree head not valid")
        return 2

    cur = read_tree_head()
    if not cur:
        print("INFO: No current tree head found in {}".format(g_args.base_dir))
    else:
        if not cur.signature_valid(log_verification_key):
            print("ERROR: signature of current tree head not valid")
            return 3
        if new.tree_size() <= cur.tree_size():
            print("INFO: Fetched tree already verified, size {}".format(cur.tree_size()))
        else:
            proof = fetch_consistency_proof(cur.tree_size(), new.tree_size())
            if not proof:
                print("ERROR: unable to fetch consistency proof")
                return 4
            if consistency_proof_valid(cur, new, proof):
                consistency_verified = True
            else:
                print("ERROR: failing consistency proof check for {}->{}".format(cur.tree_size(), new.tree_size()))
                print("DEBUG: {}:{}->{}:{}\n  {}".format(cur.tree_size(),
                                                         cur.root_hash(),
                                                         new.tree_size(),
                                                         new.root_hash(),
                                                         proof.path()))
                return 5

    if g_args.bootstrap_log:
        # TODO maybe require user confirmation
        ignore_consistency = True

    store_tree_head(new)
    if consistency_verified or ignore_consistency:
        sign_and_send_sig(signing_key, new)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
