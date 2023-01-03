import requests

from . import tree


class LogClientError(Exception):
    pass


class LogClient:
    def __init__(self, base_url: str):
        self.__base_url = base_url

    def get_tree_head_to_cosign(self) -> tree.TreeHead:
        resp = self._request("GET", "get-tree-head-to-cosign")
        return tree.TreeHead(resp.text)

    def get_consistency_proof(
        self, old_size: int, new_size: int
    ) -> tree.ConsistencyProof:
        resp = self._request("GET", f"get-consistency-proof/{old_size}/{new_size}")
        return tree.ConsistencyProof(old_size, new_size, resp.text)

    def add_cosignature(self, cosig: tree.Cosignature):
        self._request("POST", "add-cosignature", data=cosig.text())

    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        url = self.__base_url + endpoint
        try:
            resp = requests.request(method, url, **kwargs)
        except requests.ConnectionError as e:
            raise LogClientError(f"{method} {url}: connection error: {e}")
        if resp.status_code != 200:
            raise LogClientError(f"{method} {url}: {resp.status_code} {resp.reason}")
        return resp
