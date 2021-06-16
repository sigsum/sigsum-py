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
import time
from math import floor
from pathlib import PurePath

# TODO maybe stop mixing dashes and underscores in directory names and filenames

BASE_URL_DEFAULT = 'http://tlog-poc.system-transparency.org:6965/'
CONFIG_DIR_DEFAULT = os.path.expanduser('~/.config/siglog-witness/')

ERR_OK                         = 0
ERR_USAGE                      = 1
ERR_TREEHEAD_READ              = 2
ERR_TREEHEAD_FETCH             = 3
ERR_TREEHEAD_SIGNATURE_INVALID = 4
ERR_TREEHEAD_INVALID           = 5
ERR_CONSISTENCYPROOF_FETCH     = 6
ERR_CONSISTENCYPROOF_INVALID   = 7
ERR_LOGKEY                     = 8
ERR_LOGKEY_FORMAT              = 9
ERR_SIGKEYFILE                 = 10
ERR_SIGKEYFILE_MISSING         = 11
ERR_SIGKEY_FORMAT              = 12
ERR_NYI                        = 13
ERR_COSIG_POST                 = 14

class Parser:
    def __init__(self):
        p = argparse.ArgumentParser(
            description='Sign the most recently published tree head from a given siglog, after verifying it against an older tree.')

        p.add_argument('--bootstrap-log',
                       action='store_true',
                       help="Sign and save fetched tree head without verifying a consistency proof against a previous tree head. "
                       "NOTE: Requires user intervention.")

        p.add_argument('-d', '--base-dir',
                       default=CONFIG_DIR_DEFAULT,
                       help="Configuration directory ({})".format(CONFIG_DIR_DEFAULT))

        p.add_argument('-g', '--generate-signing-key',
                       action='store_true',
                       help="Generate signing key if missing. NOTE: Requires user intervention.")

        p.add_argument('-l', '--log-verification-key',
                       help="Log verification key")

        p.add_argument('--save-config',
                       action='store_true',
                       help="Save command line options to the configuration file")

        p.add_argument('-s', '--sigkey-file',
                       default='signing_key',
                       help="Signing key file ($base_dir/signing_key)")

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

    def timestamp_valid(self, now):
        ts_sec = self.timestamp()
        ts_asc = time.ctime(ts_sec)
        if ts_sec < now - 12 * 3600:
            return (ERR_OK,
                    "WARNING: Tree head timestamp too old: {} ({})".format(ts_sec, ts_asc))
        if ts_sec > now + 12 * 3600:
            return (ERR_OK,
                    "WARNING: Tree head timestamp too new: {} ({})".format(ts_sec, ts_asc))

    def history_valid(self, prev):
        if self.tree_size() < prev.tree_size():
            return (ERR_TREEHEAD_INVALID,
                    "ERROR: Log is shrinking: {} < {} ".format(self.tree_size(),
                                                               prev.tree_size()))

        if self.timestamp() < prev.timestamp():
            return (ERR_TREEHEAD_INVALID,
                    "ERROR: Log is time traveling: {} < {} ".format(time.ctime(self.timestamp()),
                                                                    time.ctime(prev.timestamp())))

        if self.timestamp() == prev.timestamp() and \
           self.root_hash() == prev.root_hash() and \
           self.tree_size() == prev.tree_size():
            return (ERR_OK,
                    "INFO: Fetched head of tree of size {} already seen".format(prev.tree_size()))

        if self.root_hash() == prev.root_hash() and \
           self.tree_size() != prev.tree_size():
            return (ERR_TREEHEAD_INVALID,
                    "ERROR: Tree size has changed but hash has not: "
                    "{}: {} != {}".format(self.root_hash(),
                                          self.tree_size(),
                                          prev.tree_size()))

        if self.root_hash() != prev.root_hash() and \
           self.tree_size() == prev.tree_size():
            return (ERR_TREEHEAD_INVALID,
                    "ERROR: Hash has changed but tree size has not: "
                    "{}: {} != {}".format(self.tree_size(),
                                          self.root_hash(),
                                          prev.root_hash()))

        # Same hash and size but new timestamp is ok.

        proof, err = fetch_consistency_proof(prev.tree_size(), self.tree_size())
        if err: return err
        if not consistency_proof_valid(prev, self, proof):
            errmsg = "ERROR: failing consistency proof check for {}->{}\n".format(prev.tree_size(),
                                                                                  self.tree_size())
            errmsg += "DEBUG: {}:{}->{}:{}\n  {}".format(prev.tree_size(),
                                                         prev.root_hash(),
                                                         self.tree_size(),
                                                         self.root_hash(),
                                                         proof.path())
            return ERR_CONSISTENCYPROOF_INVALID, errmsg


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

def make_base_dir_maybe():
    dirname = os.path.expanduser(g_args.base_dir)
    try:
        os.stat(dirname)
    except FileNotFoundError:
        os.makedirs(dirname, mode=0o700)

def read_tree_head(filename):
    try:
        with open(filename, mode='r') as f:
            return TreeHead(f.read())
    except FileNotFoundError:
        return None

def read_tree_head_and_verify(log_verification_key):
    fn = str(PurePath(os.path.expanduser(g_args.base_dir), 'signed_tree_head'))
    tree_head = read_tree_head(fn)
    if not tree_head:
        return None, (ERR_TREEHEAD_READ,
                      "ERROR: unable to read file {}".format(fn))

    if not tree_head.signature_valid(log_verification_key):
        return None, (ERR_TREEHEAD_SIGNATURE_INVALID,
                      "ERROR: signature of stored tree head invalid")

    return tree_head, None

def store_tree_head(tree_head):
    path = str(PurePath(os.path.expanduser(g_args.base_dir), 'signed_tree_head'))
    with open(path, mode='w+b') as f:
        f.write(tree_head.text())

def fetch_tree_head_and_verify(log_verification_key):
    req = requests.get(g_args.base_url + 'st/v0/get-tree-head-to-sign')
    if req.status_code != 200:
        return None, (ERR_TREEHEAD_FETCH,
                      "ERROR: unable to fetch new tree head: {}".format(req.status_code))

    tree_head = TreeHead(req.content.decode())
    if not tree_head.signature_valid(log_verification_key):
        return None, (ERR_TREEHEAD_SIGNATURE_INVALID,
                      "ERROR: signature of fetched tree head invalid")

    return tree_head, None

def fetch_consistency_proof(first, second):
    post_data = 'old_size={}\n'.format(first)
    post_data += 'new_size={}\n'.format(second)
    req = requests.post(g_args.base_url + 'st/v0/get-consistency-proof', post_data)
    if req.status_code != 200:
        return None, (ERR_CONSISTENCYPROOF_FETCH,
                      "ERROR: unable to fetch consistency proof: {}".format(req.status_code))
    return ConsistencyProof(req.content.decode()), None

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

def sign_send_store_tree_head(signing_key, tree_head):
    hash = sha256(signing_key.verify_key.encode())
    signature = signing_key.sign(tree_head.serialise()).signature

    post_data = 'signature={}\n'.format(hexlify(signature).decode('ascii'))
    post_data += 'key_hash={}\n'.format(hash.hexdigest())

    req = requests.post(g_args.base_url + 'st/v0/add-cosignature', post_data)
    if req.status_code != 200:
        return (ERR_COSIG_POST,
                "ERROR: Unable to post signature to log: {} => {}: {}". format(req.url,
                                                                               req.status_code,
                                                                               req.text))
    # Store only when all else is done. Next invocation will treat a
    # stored tree head as having been verified.
    store_tree_head(tree_head)

def ensure_log_verification_key():
    if not g_args.log_verification_key:
        return None, (ERR_LOGKEY, "ERROR: missing log verification key")
    try:
        log_verification_key = nacl.signing.VerifyKey(g_args.log_verification_key, encoder=nacl.encoding.HexEncoder)
    except:
        return None, (ERR_LOGKEY_FORMAT,
                      "ERROR: invalid log verification key: {}".format(g_args.log_verification_key))

    assert(log_verification_key is not None)
    return log_verification_key, None

def generate_and_store_sigkey(fn):
    print("INFO: Generating signing key and writing it to {}".format(fn))
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    print("INFO: verification key: {}".format(verify_key.encode(nacl.encoding.HexEncoder).decode('ascii')))
    with open(fn, 'w') as f:
        os.chmod(f.fileno(), S_IRUSR)
        f.write(signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('ascii'))

def read_sigkeyfile(fn):
    s = os.stat(fn, follow_symlinks=False)
    if not S_ISREG(s.st_mode):
        return None, (ERR_SIGKEYFILE,
                      "ERROR: Signing key file {} must be a regular file".format(fn))
    if S_IMODE(s.st_mode) & 0o077 != 0:
        return None, (ERR_SIGKEYFILE,
                      "ERROR: Signing key file {} permissions too lax: {:04o}".format(fn, S_IMODE(s.st_mode)))

    with open(fn, 'r') as f:
        try:
            signing_key = nacl.signing.SigningKey(f.readline().strip(), nacl.encoding.HexEncoder)
        except:
            return None, (ERR_SIGKEY_FORMAT,
                          "ERROR: Invalid signing key in {}".format(fn))

    assert(signing_key is not None)
    return signing_key, None


# Read signature key from file, or generate one and write it to file.
def ensure_sigkey(fn):
    try:
        os.stat(fn, follow_symlinks=False)
    except FileNotFoundError:
        if not g_args.generate_signing_key:
            return None, (ERR_SIGKEYFILE_MISSING,
                          "ERROR: Signing key file {} missing. "
                          "Use --generate-signing-key to create one.".format(fn))

        if not user_confirm("Really generate a new signing key and store it in {}?".format(fn)):
            return None, (ERR_SIGKEYFILE_MISSING,
                          "ERROR: Signing key file {} missing".format(fn))

        generate_and_store_sigkey(fn)
        return read_sigkeyfile(fn)

    if g_args.generate_signing_key:
        return None, (ERR_USAGE,
                      "ERROR: Signing key file {} already existing".format(fn))
    return read_sigkeyfile(fn)


def user_confirm(prompt):
    resp = input(prompt + ' y/n> ').lower()
    if resp and resp[0] == 'y':
        return True
    return False

def main(args):
    global g_args
    g_args = Parser()
    parse_args(args)            # get base_dir
    parse_config(str(PurePath(g_args.base_dir, 'siglog-witness.conf')))
    parse_args(args)            # override config file options
    if g_args.save_config:
        # TODO write to config file
        return ERR_NYI, "ERROR: --save-config is not yet implemented"

    now = floor(time.time())
    consistency_verified = False
    ignore_consistency = False

    make_base_dir_maybe()

    log_verification_key, err = ensure_log_verification_key()
    if err: return err

    signing_key, err = ensure_sigkey(str(PurePath(g_args.base_dir, g_args.sigkey_file)))
    if err: return err

    cur_tree_head, err = read_tree_head_and_verify(log_verification_key)
    if err:
        new_tree_head, err2 = fetch_tree_head_and_verify(log_verification_key)
        if err2: return err2

        if not g_args.bootstrap_log:
            return err

        print("\nWARNING: We have only seen one single tree head from the\n"
              "log {},\n"
              "representing a tree of size {}. We are therefore unable to\n"
              "verify that the tree it represents is really a superset of an\n"
              "earlier version of the tree in this log.\n"
              "\nWe are effectively signing this tree head blindly.\n".format(g_args.base_url,
                                                                              new_tree_head.tree_size()))
        if user_confirm("Really sign head for tree of size {} and upload "
                        "the signature?".format(new_tree_head.tree_size())):
            err3 = sign_send_store_tree_head(signing_key, new_tree_head)
            if err3: return err3

        return 0, None
    else:
        if g_args.bootstrap_log:
            return (ERR_USAGE,
                    "ERROR: Valid tree head found: --bootstrap-log not allowed")

    new_tree_head, err = fetch_tree_head_and_verify(log_verification_key)
    if err: return err

    err = new_tree_head.timestamp_valid(now)
    if err: return err

    err = new_tree_head.history_valid(cur_tree_head)
    if err: return err

    if not cur_tree_head.signature_valid(log_verification_key):
        return ERR_TREEHEAD_SIGNATURE_INVALID, "ERROR: signature of current tree head invalid"

    err = sign_send_store_tree_head(signing_key, new_tree_head)
    if err: return err

    return 0, None

if __name__ == '__main__':
    status = main(sys.argv)
    if status[1]:
        print(status[1])
    sys.exit(status[0])
