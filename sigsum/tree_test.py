import pytest
from . import tree

class TestTreeHead:
    def test_init(self):
        data = """timestamp=1000
tree_size=10
root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
signature=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
"""
        tree_head = tree.TreeHead(data)
        assert tree_head.timestamp == 1000
        assert tree_head.tree_size == 10
        assert len(tree_head.root_hash) == 32

class TestConsistencyProof:
    def test_init(self):
        data = """consistency_path=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
consistency_path=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""
        consistency_proof = tree.ConsistencyProof(10, 17, data)
        assert consistency_proof.old_size() == 10
        assert consistency_proof.new_size() == 17
        assert len(consistency_proof.path()) == 2
