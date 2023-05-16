#! /usr/bin/env python3

# Sign the most recently published tree head from a given ST log,
# after verifying a consistency proof from an already verified tree
# head to this new tree head.

# A verified tree head is expected to be found in the file
# ~/.config/sigsum-witness/signed-tree-head . It's updated once a
# newer tree head has been verified successfully.

# If the config file ~/.config/sigsum-witness/sigsum-witness.conf
# exists and is readable, options are read from it. Options read from
# the config file can be overridden on the command line.

# Pubkey from secret key:
# sigkey = nacl.signing.SigningKey('badc0ffee123456...', nacl.encoding.HexEncoder)
# sigkey.verify_key.encode(nacl.encoding.HexEncoder)

import argparse
import logging
import os
import stat
import sys
import threading
import time
from hashlib import sha256
from math import floor
from pathlib import Path, PurePath
from stat import *

import nacl.encoding
import nacl.signing
import prometheus_client as prometheus

import sigsum.ascii
import sigsum.client
import sigsum.crypto
import sigsum.tree

BASE_URL_DEFAULT = 'http://poc.sigsum.org:4780/'
CONFIG_DIR_DEFAULT = os.path.expanduser('~/.config/sigsum-witness/')

LOGGER = logging.getLogger("sigsum-witness")

# Metrics
SIGNING_ATTEMPTS = prometheus.Counter(
    "sigsum_witness_signing_attempts_total", "Total number of signing attempts"
)
SIGNING_ERROR = prometheus.Counter(
    "sigsum_witness_signing_errors_total", "Total number of signing error"
)
LAST_SUCCESS = prometheus.Gauge(
    "sigsum_witness_last_success_timestamp_seconds", "Time of last successful signature"
)
LOG_TIMESTAMP = prometheus.Gauge(
    "sigsum_witness_log_timestamp_seconds", "Latest cosignature timestamp."
)
LOG_TREE_SIZE = prometheus.Gauge(
    "sigsum_witness_log_tree_size", "Latest tree size from the log."
)

ERR_OK                         = 0
ERR_USAGE                      = os.EX_USAGE
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
            description='Sign the most recently published tree head from a given sigsum log, after verifying it against an older tree.')

        p.add_argument('--bootstrap-log',
                       action='store_true',
                       help="Sign and save fetched tree head without verifying a consistency proof against a previous tree head. "
                       "NOTE: Requires user intervention.")

        p.add_argument("--once",
                       action='store_true',
                       help="Verify and cosign the most recent tree head, and then exit.")

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

        p.add_argument(
            "-s",
            "--sigkey-file",
            default="signing-key",
            help="Signing key file, relative to $base_dir if not an absolute path (signing-key)",
        )
        p.add_argument(
            "--ssh-agent",
            action="store_true",
            help="Use ssh-agent.  The agent must already be running and have exactly one key of type ed25519.",
        )

        p.add_argument(
            "-u",
            "--base-url",
            default=BASE_URL_DEFAULT,
            help="Log base URL ({})".format(BASE_URL_DEFAULT),
        )

        p.add_argument(
            "-i",
            "--interval",
            action="store",
            type=int,
            default=30,
            help="Interval between signing attempt, in seconds (30)",
        )

        p.add_argument(
            "-v",
            "--verbose",
            action="store_const",
            const=logging.DEBUG,
            default=logging.INFO,
            dest="log_level",
            help="Increase verbosity",
        )

        p.add_argument(
            "-p",
            "--metrics-port",
            action="store",
            type=int,
            default=8000,
            help="Port of the HTTP server to expose Prometheus metrics.",
        )

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

def history_valid(client: sigsum.client.LogClient, next : sigsum.tree.TreeHead, prev : sigsum.tree.TreeHead):
    if next.size < prev.size:
        return (ERR_TREEHEAD_INVALID,
                "ERROR: Log is shrinking: {} < {} ".format(next.size,
                                                           prev.size))

    if next.size == prev.size:
        if next.root_hash != prev.root_hash:
            return (ERR_TREEHEAD_INVALID,
                "ERROR: Hash has changed but tree size has not: "
                "{}: {} != {}".format(next.size,
                                      next.root_hash,
                                      prev.root_hash))
        print("INFO: Signing re-published head of tree of size {}".format(next.size))
        return None         # Success

    proof = client.get_consistency_proof(prev.size, next.size)
    if not consistency_proof_valid(prev, next, proof):
        errmsg = "ERROR: failing consistency proof check for {}->{}\n".format(prev.size,
                                                                              next.size)
        errmsg += "DEBUG: {}:{}->{}:{}\n  {}".format(
            prev.size, prev.root_hash, next.size, next.root_hash, proof.path
        )
        return ERR_CONSISTENCYPROOF_INVALID, errmsg

    return None             # Success


def make_base_dir_maybe():
    dirname = os.path.expanduser(g_args.base_dir)
    try:
        os.stat(dirname)
    except FileNotFoundError:
        os.makedirs(dirname, mode=0o700)

def read_tree_head(filename):
    try:
        with open(filename, mode='r') as f:
            return sigsum.tree.TreeHead.fromascii(f.read())
    except sigsum.ascii.ASCIIDecodeError as err:
        die(ERR_TREEHEAD_READ, f"{filename}: {err}")
    except FileNotFoundError:
        return None

def read_tree_head_and_verify(log_verification_key):
    fn = str(PurePath(os.path.expanduser(g_args.base_dir), 'signed-tree-head'))
    tree_head = read_tree_head(fn)
    if not tree_head:
        return None, (ERR_TREEHEAD_READ,
                      "ERROR: unable to read file {}".format(fn))

    if not tree_head.signature_valid(log_verification_key):
        return None, (ERR_TREEHEAD_SIGNATURE_INVALID,
                      "ERROR: signature of stored tree head invalid")

    return tree_head, None

def store_tree_head(tree_head):
    path = str(PurePath(os.path.expanduser(g_args.base_dir), 'signed-tree-head'))
    with open(path, mode='w+b') as f:
        f.write(tree_head.ascii())


def fetch_tree_head_and_verify(client: sigsum.client.LogClient, log_verification_key):
    try:
        tree_head = client.get_tree_head_to_cosign()
    except sigsum.client.LogClientError as err:
        return None, (ERR_TREEHEAD_FETCH, f"unable to fetch new tree head: {err}")

    if not tree_head.signature_valid(log_verification_key):
        return None, (ERR_TREEHEAD_SIGNATURE_INVALID,
                      "ERROR: signature of fetched tree head invalid")

    return tree_head, None

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
def consistency_proof_valid(first, second, proof) -> bool:
    assert(first.size == proof.old_size)
    assert(second.size == proof.new_size)

    path = proof.path
    if len(path) == 0:
        return False
    if numbits(first.size) == 1:
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


def sign_send_store_tree_head(
    client: sigsum.client.LogClient, signer, timestamp : int, log_key, tree_head
):
    signature = signer.sign(tree_head.to_cosigned_data(
        timestamp, sha256(log_key.encode()).digest()))
    cosig = sigsum.tree.Cosignature(sha256(signer.public()).digest(), timestamp, signature)
    try:
        client.add_cosignature(cosig)
    except sigsum.client.LogClientError as err:
        return (ERR_COSIG_POST, f"Unable to post signature to log: {err}")

    LOG_TIMESTAMP.set(timestamp)
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


# Read signature key from file, or generate one and write it to file.
def ensure_sigkey(fn, generate: bool):
    if generate:
        if fn.exists():
            die(ERR_USAGE, f"Signing key file {fn} already existing")
        if user_confirm(f"Really generate a new signing key and store it in {fn}?"):
            generate_and_store_sigkey(fn)
    try:
        check_keyfile_permission(fn)
        return sigsum.crypto.KeyfileSigner(fn)
    except FileNotFoundError:
        die(
            ERR_SIGKEYFILE_MISSING,
            f"Signing key file {fn} missing. Use --generate-signing-key to create one.",
        )
    except IsADirectoryError:
        die(ERR_SIGKEYFILE, f"Signing key file {fn} must be a regular file.")
    except sigsum.crypto.KeyfileError:
        die(ERR_SIGKEY_FORMAT, f"Invalid signing key in {fn}")


def check_keyfile_permission(fp):
    perm = stat.S_IMODE(fp.stat().st_mode)
    if perm & 0o077 != 0:
        die(ERR_SIGKEYFILE, f"Signing key file {fp} permissions too lax: {perm:04o}.")


def user_confirm(prompt):
    resp = input(prompt + ' y/n> ').lower()
    if resp and resp[0] == 'y':
        return True
    return False


class Witness(threading.Thread):
    def __init__(self, client: sigsum.client.LogClient, signer, log_verification_key, cur_tree_head):
        super().__init__()
        self.client = client
        self.signer = signer
        self.log_verification_key = log_verification_key
        self.cur_tree_head = cur_tree_head
        self.exit = threading.Event()

    def run(self):
        while not self.exit.wait(g_args.interval):
            SIGNING_ATTEMPTS.inc()
            try:
                err = self.sign_once()
            except Exception as e:
                LOGGER.exception(e)
                SIGNING_ERROR.inc()
                continue
            if err:
                LOGGER.error(err[1])
                SIGNING_ERROR.inc()
            else:
                LAST_SUCCESS.set_to_current_time()

    def sign_once(self):
        new_tree_head, err = fetch_tree_head_and_verify(
            self.client, self.log_verification_key
        )
        if err:
            return err
        LOG_TREE_SIZE.set(new_tree_head.size)
        err = history_valid(self.client, new_tree_head, self.cur_tree_head)
        if err:
            return err
        if not self.cur_tree_head.signature_valid(self.log_verification_key):
            return (
                ERR_TREEHEAD_SIGNATURE_INVALID,
                "ERROR: signature of current tree head invalid",
            )
        err = sign_send_store_tree_head(
            self.client, self.signer, floor(time.time()), self.log_verification_key, new_tree_head)
        if err:
            return err
        self.cur_tree_head = new_tree_head


def main():
    global g_args
    g_args = Parser()
    args = sys.argv
    parse_args(args)            # get base_dir
    parse_config(str(PurePath(g_args.base_dir, 'sigsum-witness.conf')))
    parse_args(args)            # override config file options
    if g_args.save_config:
        # TODO write to config file
        die(ERR_NYI, "--save-config is not yet implemented")
    logging.basicConfig(
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            level=g_args.log_level,
            )

    consistency_verified = False
    ignore_consistency = False

    make_base_dir_maybe()

    log_verification_key, err = ensure_log_verification_key()
    if err:
        die(*err)

    if g_args.ssh_agent:
        sock = os.getenv("SSH_AUTH_SOCK")
        if not sock:
            die(ERR_USAGE, "SSH_AUTH_SOCK is not set")
        try:
            signer = sigsum.crypto.SSHAgentSigner(sock)
        except sigsum.crypto.SSHAgentError as e:
            die(ERR_USAGE, str(e))
    else:
        signer = ensure_sigkey(
            Path(g_args.base_dir, g_args.sigkey_file), g_args.generate_signing_key
        )

    client = sigsum.client.LogClient(g_args.base_url)

    cur_tree_head, err = read_tree_head_and_verify(log_verification_key)
    if err:
        new_tree_head, err2 = fetch_tree_head_and_verify(client, log_verification_key)
        if err2:
            die(*err2)

        if not g_args.bootstrap_log:
            die(*err)

        print("\nWARNING: We have only seen one single tree head from the\n"
              "log {},\n"
              "representing a tree of size {}. We are therefore unable to\n"
              "verify that the tree it represents is really a superset of an\n"
              "earlier version of the tree in this log.\n"
              "\nWe are effectively signing this tree head blindly.\n".format(g_args.base_url,
                                                                              new_tree_head.size))
        if user_confirm("Really sign head for tree of size {} and upload "
                        "the signature?".format(new_tree_head.size)):
            err3 = sign_send_store_tree_head(
                client, signer, floor(time.time()), log_verification_key, new_tree_head)
            if err3:
                die(*err3)

        return
    if g_args.bootstrap_log:
        die(ERR_USAGE, "Valid tree head found: --bootstrap-log not allowed")

    # Start up the server to expose the metrics.
    LOGGER.info(f"Starting metrics server on port {g_args.metrics_port}")
    prometheus.start_http_server(g_args.metrics_port)

    LOGGER.info("Starting witness")
    LOGGER.info(f"Public key: {signer.public().hex()}")
    thread = Witness(client, signer, log_verification_key, cur_tree_head)
    if g_args.once:
        err = thread.sign_once()
        if err:
            die(1, err[1])
    else:
        thread.start()
        try:
            time.sleep(100000)
        except KeyboardInterrupt:
            thread.exit.set()
            thread.join()


def die(code, msg=None):
    if msg:
        print("ERROR:", msg, file=sys.stderr)
    sys.exit(code)



if __name__ == '__main__':
    main()
