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
        ([("foo", "bar", "baz")], "foo=bar baz\n"),
    ],
    ids=["empty", "simple", "list", "int", "bytes", "single-value-shortcut", "tuple"],
)
def test_dumps(data, expected):
    assert ascii.dumps(data) == expected


def test_dumps_type_error():
    with pytest.raises(
        TypeError, match="Object of type object is not ASCII serializable"
    ):
        ascii.dumps([("foo", object())])

@pytest.mark.parametrize(
    "line, name, count, expected",
    [
        ("foo=bar", "foo", 1, ["bar"]),
        ("foo=bar baz", "foo", 2, ["bar", "baz"]),
    ],
    ids=["single value", "two values"]
)
def test_parse_line(line, name, count, expected):
    assert ascii.parse_line(line, name, count) == expected

def test_parse_line_invalid():
    line = "foo=bar baz"
    expected = ["bar", "baz"]
    assert ascii.parse_line(line, "foo", 2) == expected
    with pytest.raises(ascii.ASCIIDecodeError):
        ascii.parse_line(line, "foo", 1)
    with pytest.raises(ascii.ASCIIDecodeError):
        ascii.parse_line(line, "foo", 3)
    with pytest.raises(ascii.ASCIIDecodeError):
        ascii.parse_line(line, "fo0", 2)
