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
import flask

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

class WitnessError(Exception):
    def __init__(self, code: int, msg: str):
        self.code = code
        self.msg = msg

class Parser:
    def __init__(self):
        p = argparse.ArgumentParser(
            description='Witness a given sigsum log, verifying and cosigning tree heads provided by the log.')

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
            "-v",
            "--verbose",
            action="store_const",
            const=logging.DEBUG,
            default=logging.INFO,
            dest="log_level",
            help="Increase verbosity",
        )

        p.add_argument(
            "--metrics-port",
            action="store",
            type=int,
            default=8000,
            help="Port of the HTTP server to expose Prometheus metrics.",
        )

        p.add_argument(
            "--listen-address",
            action="store",
            default="localhost",
            help="Address to listen on",
        )

        p.add_argument(
            "--listen-port",
            action="store",
            type=int,
            default=5000,
            help="Port to listen to.",
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

class WitnessState:
    def __init__(self, sth_file_name: str, signer, log_verification_key):
        self.sth_file_name = sth_file_name
        self.signer = signer
        self.log_verification_key = log_verification_key
        self.log_key_hash = sha256(log_verification_key.encode()).digest()
        self.cur_tree_head = None

    def init_tree_head(self, bootstrap: bool) -> None:
        if self.cur_tree_head != None:
            raise WitnessError(ERR_TREEHEAD_READ,
                               "ERROR: current tree head already initialized")
        try:
            with open(self.sth_file_name, mode='r') as f:
                if bootstrap:
                    raise WitnessError(ERR_TREEHEAD_READ,
                                       "ERROR: tree head file exists, even though bootstrap was requested")
                tree_head = sigsum.tree.TreeHead.fromascii(f.read())
                if not tree_head.signature_valid(self.log_verification_key):
                    raise WitnessError(ERR_TREEHEAD_SIGNATURE_INVALID,
                                       "ERROR: signature of stored tree head invalid")
                self.cur_tree_head = tree_head

        except sigsum.ascii.ASCIIDecodeError as err:
            raise WitnessError(ERR_TREEHEAD_READ, f"{filename}: {err}")
        except FileNotFoundError:
            if not bootstrap:
                raise WitnessError(ERR_TREEHEAD_READ,
                                   "ERROR: unable to read file {}".format(self.sth_file_name))

            self.cur_tree_head = sigsum.tree.TreeHead.make_empty()

    def store_tree_head(self, tree_head: sigsum.tree.TreeHead):
        # TODO: Do atomic replace of file contents
        with open(self.sth_file_name, mode='w+b') as f:
            f.write(tree_head.ascii())
        self.cur_tree_head = tree_head

    def cur_size(self) -> int:
        return self.cur_tree_head.size

    # Check that tree head is properly signed and consistent, then
    # update state on disk and in memory.
    def update_tree_head(self, tree_head: sigsum.tree.TreeHead,
                         proof: sigsum.tree.ConsistencyProof):
        if not tree_head.signature_valid(self.log_verification_key):
            raise WitnessError(ERR_TREEHEAD_SIGNATURE_INVALID,
                               "ERROR: signature of new tree head invalid")

        if tree_head.size < self.cur_tree_head.size:
            raise WitnessError(ERR_TREEHEAD_INVALID,
                               "ERROR: Log is shrinking: {} < {} ".format(
                                   tree_head.size, self.cur_tree_head.size))
        if not proof.proof_valid(self.cur_tree_head, tree_head):
            raise WitnessError(ERR_CONSISTENCYPROOF_INVALID,
                               "ERROR: failing consistency proof check for {}->{}\n".format(
                                   tree_head.size, self.cur_tree_head.size))
        self.store_tree_head(tree_head)

    def cosign_tree_head(self, timestamp: int) -> sigsum.tree.Cosignature:
        signature = self.signer.sign(self.cur_tree_head.to_cosigned_data(
            self.log_key_hash, timestamp))
        return sigsum.tree.Cosignature(sha256(self.signer.public()).digest(), timestamp, signature)

def make_base_dir_maybe():
    dirname = os.path.expanduser(g_args.base_dir)
    try:
        os.stat(dirname)
    except FileNotFoundError:
        os.makedirs(dirname, mode=0o700)

def ensure_log_verification_key() -> nacl.signing.VerifyKey:
    if not g_args.log_verification_key:
        raise WitnessError(ERR_LOGKEY, "ERROR: missing log verification key")
    try:
        log_verification_key = nacl.signing.VerifyKey(g_args.log_verification_key, encoder=nacl.encoding.HexEncoder)
    except:
        raise WitnessError(ERR_LOGKEY_FORMAT,
                      "ERROR: invalid log verification key: {}".format(g_args.log_verification_key))

    assert(log_verification_key is not None)
    return log_verification_key

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

app = flask.Flask(__name__)

g_state_lock = threading.Lock()
g_state = None

@app.route("/get-tree-size/<key_hash>", methods=["GET"])
def get_tree_size(key_hash):
    global g_state, g_state_lock
    with g_state_lock:
        try:
            if bytes.fromhex(key_hash) != g_state.log_key_hash:
                return flask.make_response("unknown log", 403)
        except Exception as e:
            return flask.make_response("invalid request: " + str(e), 400)
        return f"size={g_state.cur_size()}\n"

@app.route("/add-tree-head", methods=["POST"])
def add_tree_head():
    global g_state, g_state_lock
    if flask.request.content_length > 10000:
        return flask.make_response("request too large", 400)
    data = flask.request.get_data()
    try:
        add_tree_head = sigsum.tree.AddTreeHeadRequest.fromascii(data.decode("ascii"))
    except Exception as e:
        return flask.make_response("invalid request: " + str(e), 400)

    with g_state_lock:
        if add_tree_head.key_hash != g_state.log_key_hash:
            return flask.make_response("unknown log", 403)
        if add_tree_head.old_size != g_state.cur_size():
            return flask.make_response("bad old size, expected: {}".format(g_state.cur_size()), 409)
        try:
            g_state.update_tree_head(add_tree_head.tree_head, add_tree_head.proof)
        except WitnessError as e:
            if e.code == ERR_CONSISTENCYPROOF_INVALID:
                return flask.make_response("not consistent: " + e.msg, 422)
            return flask.make_response(e.msg, 403)

        cs = g_state.cosign_tree_head(floor(time.time()))
        return flask.make_response(cs.ascii())

def set_content_type(resp: flask.Response) -> flask.Response:
    resp.headers["content-type"] = "text/plain"
    return resp

def main():
    global g_args, g_state, app
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

    try:
        log_verification_key = ensure_log_verification_key()
    except WitnessError as e:
        die(e.code, e.msg)
    except:
        die(ERR_USAGE, str(e))

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

    g_state = WitnessState(PurePath(os.path.expanduser(g_args.base_dir), 'signed-tree-head'),
                         signer, log_verification_key)
    try:
        g_state.init_tree_head(g_args.bootstrap_log)
    except WitnessError as e:
        die(e.code, e.msg)

    # Start up the server to expose the metrics.
    LOGGER.info(f"Starting metrics server on port {g_args.metrics_port}")
    prometheus.start_http_server(g_args.metrics_port)

    LOGGER.info("Starting witness")
    LOGGER.info(f"Public key: {signer.public().hex()}")
    app.after_request(set_content_type)
    app.run(host=g_args.listen_address, port=g_args.listen_port)

def die(code, msg=None):
    if msg:
        print("ERROR:", msg, file=sys.stderr)
    sys.exit(code)



if __name__ == '__main__':
    main()
