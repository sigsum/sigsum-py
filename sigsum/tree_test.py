from . import tree


class TestTreeHead:
    def test_fromascii(self):
        data = """timestamp=1000
tree_size=10
root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
signature=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
"""
        tree_head = tree.TreeHead.fromascii(data)
        assert tree_head.timestamp == 1000
        assert tree_head.tree_size == 10
        assert tree_head.root_hash == bytes.fromhex("cc" * 32)
        assert tree_head.signature == bytes.fromhex("dd" * 64)

    def test_ascii(self):
        sth = tree.TreeHead(
            1000, 10, bytes.fromhex("cc" * 32), bytes.fromhex("dd" * 64)
        )
        assert (
            sth.ascii()
            == b"""timestamp=1000
tree_size=10
root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
signature=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
"""
        )


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
