from . import tree

import nacl.encoding
import nacl.signing


class TestTreeHead:
    def test_fromascii(self):
        data = """size=10
root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
signature=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
"""
        tree_head = tree.TreeHead.fromascii(data)
        assert tree_head.size == 10
        assert tree_head.root_hash == bytes.fromhex("cc" * 32)
        assert tree_head.signature == bytes.fromhex("dd" * 64)

    def test_ascii(self):
        sth = tree.TreeHead(
            10, bytes.fromhex("cc" * 32), bytes.fromhex("dd" * 64)
        )
        assert (
            sth.ascii()
            == b"""size=10
root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
signature=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
"""
        )

    def test_to_signed_data(self):
        sth = tree.TreeHead(10, bytes.fromhex("cc" * 32), bytes.fromhex("dd" * 64))
        key_hash = bytes.fromhex("ee" * 32)
        assert sth.to_signed_data(key_hash) == b"""sigsum.org/v1/tree/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
10
zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=
"""

    def test_signature_valid(self):
        data="""size=4
root_hash=7bca01e88737999fde5c1d6ecac27ae3cb49e14f21bcd3e7245c276877b899c9
signature=c60e5151b9d0f0efaf57022c0ec306c0f0275afef69333cc89df4fda328c87949fcfa44564f35020938a4cd6c1c50bc0349b2f54b82f5f6104b9cd52be2cd90e
"""
        tree_head = tree.TreeHead.fromascii(data)

        pub_key = nacl.signing.VerifyKey("dea4c37c360568e528b76bb67bf821a37ece0f3f46928603df006db4f08e9750", encoder=nacl.encoding.HexEncoder)
        assert tree_head.signature_valid(pub_key)

        tree_head.size = tree_head.size + 1
        assert not tree_head.signature_valid(pub_key)

    def test_to_cosigned_data(self):
        sth = tree.TreeHead(10, bytes.fromhex("cc" * 32), bytes.fromhex("dd" * 64))
        key_hash = bytes.fromhex("ee" * 32)
        timestamp = 1234567
        assert sth.to_cosigned_data(key_hash, timestamp) == b"""cosignature/v1
time 1234567
sigsum.org/v1/tree/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
10
zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=
"""

class TestConsistencyProof:
    def test_fromascii(self):
        data = """node_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
node_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""
        consistency_proof = tree.ConsistencyProof.fromascii(data)
        assert consistency_proof.path == [
            bytes.fromhex("aa" * 32),
            bytes.fromhex("bb" * 32),
        ]


class TestCosignature:
    def test_ascii(self):
        cosig = tree.Cosignature(b"\xaa" * 32, 17, b"\xbb" * 64)
        assert (
            cosig.ascii()
            == b"cosignature=v1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 17 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        )
