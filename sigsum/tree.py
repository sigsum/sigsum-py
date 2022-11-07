from .ascii import loads, dumps

class TreeHead:
    def __init__(self, sth_data):
        self.__data = loads(sth_data)
        assert(len(self.__data) == 4)
        assert('timestamp' in self.__data)
        assert('tree_size' in self.__data)
        assert('root_hash' in self.__data)
        assert('signature' in self.__data)

    @property
    def timestamp(self):
        return self.__data.getint('timestamp')

    @property
    def tree_size(self):
        return self.__data.getint('tree_size')

    @property
    def root_hash(self):
        return self.__data.getbytes('root_hash')

    def text(self):
        return dumps(self.__data).encode('ascii')

    def to_signed_data(self, pubkey):
        namespace = 'tree_head:v0:{}@sigsum.org'.format(hexlify(sha256(pubkey.encode()).digest()).decode())
        msg = struct.pack('!QQ', self.timestamp, self.tree_size)
        msg += self.root_hash
        assert(len(msg) == 8 + 8 + 32)
        return ssh_to_sign(namespace, 'sha256', sha256(msg).digest())

    def signature_valid(self, pubkey):
        # Guard against tree head with >1 signature -- don't try to
        # validate a cosigned tree head.
        sig = self.__data.getbytes('signature')
        assert(len(sig) == 64)
        data = self.to_signed_data(pubkey)
        try:
            verified_data = pubkey.verify(sig + data)
        except nacl.exceptions.BadSignatureError:
            return False
        assert(verified_data == data)
        return True

class ConsistencyProof():
    def __init__(self, old_size, new_size, consistency_proof_data):
        self.__old_size = old_size
        self.__new_size = new_size
        self.__data = loads(consistency_proof_data)
        assert(len(self.__data) == 1)
        assert('consistency_path' in self.__data)

    def old_size(self):
        return self.__old_size
    def new_size(self):
        return self.__new_size

    def path(self):
        return self.__data.getbytes('consistency_path', many=True)
