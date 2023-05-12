import difflib
import typing as t
from http import HTTPStatus

import pytest
import requests
import responses

from . import tree
from .client import LogClient, LogClientError


def ascii_params_matcher(
    expected: t.List[t.Tuple[str, str]]
) -> t.Callable[[requests.PreparedRequest], t.Tuple[bool, str]]:
    def matcher(req: requests.PreparedRequest) -> t.Tuple[bool, str]:
        print(req)
        expected_body = "\n".join(f"{k}={v}" for k, v in expected).encode()
        if req.body is not None and req.body.strip() == expected_body:
            return True, ""
        return False, "request.body doesn't match"

    return matcher


@responses.activate
def test_get_tree_head_to_cosign():
    responses.get(
        "https://sigsum.log/get-next-tree-head",
        body="\n".join(
            [
                "size=10",
                "root_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "signature=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ]
        ),
    )
    client = LogClient("https://sigsum.log/")
    tree_head = client.get_tree_head_to_cosign()
    assert tree_head.size == 10
    assert tree_head.root_hash == b"\xCC" * 32
    assert tree_head.signature == b"\xDD" * 64


@responses.activate
def test_get_consistency_proof():
    responses.get(
        "https://sigsum.log/get-consistency-proof/2/8",
        body="\n".join(
            [
                "node_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "node_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ]
        ),
    )
    client = LogClient("https://sigsum.log/")
    proof = client.get_consistency_proof(2, 8)
    assert list(proof.path) == [b"\xAA" * 32, b"\xBB" * 32]


@responses.activate
def test_add_cosignature():
    responses.post(
        "https://sigsum.log/add-cosignature",
        match=[
            ascii_params_matcher(
                [
                    (
                        "cosignature",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 17 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    )
                ]
            )
        ],
    )
    client = LogClient("https://sigsum.log/")
    client.add_cosignature(tree.Cosignature(b"\xAA" * 32, 17, b"\xBB" * 64))


def test_connection_error():
    client = LogClient("https://sigsum.log/")
    with pytest.raises(
        LogClientError,
        match="GET https://sigsum.log/get-next-tree-head: connection error",
    ):
        client.get_tree_head_to_cosign()


@responses.activate
def test_status_error():
    responses.get(
        "https://sigsum.log/get-next-tree-head",
        status=HTTPStatus.INTERNAL_SERVER_ERROR,
    )
    client = LogClient("https://sigsum.log/")
    with pytest.raises(
        LogClientError,
        match="GET https://sigsum.log/get-next-tree-head: 500 Internal Server Error",
    ):
        client.get_tree_head_to_cosign()
