from . import ascii


def test():
    pass


import pytest

@pytest.mark.parametrize(
    "data, expected",
    [
        ([], ""),
        ([("foo", ["bar"]), ("baz", ["biz"])], "foo=bar\nbaz=biz\n"),
        ([("foo", ["bar", "baz"])], "foo=bar\nfoo=baz\n"),
        ([("foo", [42])], "foo=42\n"),
        ([("foo", [b"\xDE\xAD\xBE\xEF"])], "foo=deadbeef\n"),
        ([("foo", "bar")], "foo=bar\n"),
    ],
    ids=["empty", "simple", "list", "int", "bytes", "single-value-shortcut"],
)
def test_dumps(data, expected):
    assert ascii.dumps(data) == expected


def test_dumps_type_error():
    with pytest.raises(
        TypeError, match="Object of type object is not ASCII serializable"
    ):
        ascii.dumps([("foo", [object()])])
