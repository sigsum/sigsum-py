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

    # Based in sigsum-go tree_head_test.go, revision 5cae7e582a5fff0b2849e96639988841800b7700 (before merge of checkpoint format).
    def test_signature_valid(self):
        data="""size=4
root_hash=84ec3e1ba5433358988ac74bed33a30bda42cc983b87e4940a423c2d84890f0f
signature=7e2084ded0f7625136e6c811ac7eae2cb79613cadb12a6437b391cdae3a5c915dcd30b5b5fe4fbf417a2d607a4cfcb3612d7fd4ffe9453c0d29ec002a6d47709
"""
        tree_head = tree.TreeHead.fromascii(data)

        pub_key = nacl.signing.VerifyKey("22c091e3f75497ef19015c5daf143910e20cda7295b0fd1ddf83825686efeca6", encoder=nacl.encoding.HexEncoder)
        assert tree_head.signature_valid(pub_key)

        tree_head.size = tree_head.size + 1
        assert not tree_head.signature_valid(pub_key)

class TestConsistencyProof:
    def test_fromascii(self):
        data = """consistency_path=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
consistency_path=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""
        consistency_proof = tree.ConsistencyProof.fromascii(10, 17, data)
        assert consistency_proof.path == [
            bytes.fromhex("aa" * 32),
            bytes.fromhex("bb" * 32),
        ]


class TestCosignature:
    def test_ascii(self):
        cosig = tree.Cosignature(b"\xaa" * 32, b"\xbb" * 64)
        assert (
            cosig.ascii()
            == b"cosignature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        )
