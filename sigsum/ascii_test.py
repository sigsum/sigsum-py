import io
import operator
from operator import methodcaller as M

from . import ascii


def test():
    pass


import pytest


@pytest.mark.parametrize(
    "txt, expected",
    [
        ("", {}),
        ("foo=bar", {"foo": ["bar"]}),
        ("foo=bar\nqux=42", {"foo": ["bar"], "qux": ["42"]}),
        ("foo=bar\nfoo=biz", {"foo": ["bar", "biz"]}),
        ("error=something went wrong", {"error": ["something went wrong"]}),
        ("error=a message with an = sign", {"error": ["a message with an = sign"]}),
    ],
)
def test_loads(txt, expected):
    assert ascii.loads(txt) == expected


@pytest.mark.parametrize(
    "txt, message",
    [
        ("foo", "Expecting '=' delimiter line 1"),
        ("foo=", "Expecting value after '=' line 1"),
    ],
)
def test_loads_error(txt, message):
    with pytest.raises(ascii.ASCIIDecodeError, match=message):
        ascii.loads(txt)


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


@pytest.mark.parametrize(
    "data, func, expected",
    [
        # Check that it behave like a Mapping[str, List[str]]
        ([("foo", "bar"), ("foo", "baz")], operator.itemgetter("foo"), ["bar", "baz"]),
        ([("foo", "bar"), ("foo", "baz")], len, 1),
        ([("foo", "bar"), ("foo", "baz")], lambda x: list(iter(x)), ["foo"]),
        # Check accessors
        ([("foo", "bar")], M("getone", "foo"), "bar"),
        ([("foo", "42")], M("getint", "foo"), 42),
        ([("foo", "deadbeef")], M("getbytes", "foo"), b"\xDE\xAD\xBE\xEF"),
        ([("foo", "42"), ("foo", "0")], M("getint", "foo", True), [42, 0]),
        (
            [("foo", "dead"), ("foo", "beef")],
            M("getbytes", "foo", True),
            [b"\xDE\xAD", b"\xBE\xEF"],
        ),
    ],
)
def test_asciivalue_getters(data, func, expected):
    kv = ascii.ASCIIValue(data)
    assert func(kv) == expected


@pytest.mark.parametrize(
    "data, func, error",
    [
        # missing key
        ([], M("getone", "foo"), KeyError),
        ([], M("getint", "foo"), KeyError),
        ([], M("getbytes", "foo"), KeyError),
        # too many values
        ([("foo", "bar"), ("foo", "baz")], M("getone", "foo"), ValueError),
        ([("foo", "42"), ("foo", "0")], M("getint", "foo"), ValueError),
        ([("foo", "dead"), ("foo", "beef")], M("getbytes", "foo"), ValueError),
        # strconv errors
        ([("foo", "xx")], M("getint", "foo"), ValueError),
        ([("foo", "xx")], M("getbytes", "foo"), ValueError),
    ],
)
def test_asciivalue_getters_errorrs(data, func, error):
    kv = ascii.ASCIIValue(data)
    with pytest.raises(error):
        func(kv)


def test_asciivalue_repr():
    v = ascii.ASCIIValue([("foo", "bar"), ("foo", "baz"), ("qux", "quux")])
    assert repr(v) == "ASCIIValue([('foo', 'bar'), ('foo', 'baz'), ('qux', 'quux')])"


def test_asciivalue_eq():
    v = ascii.ASCIIValue([("foo", "bar"), ("foo", "baz"), ("qux", "quux")])
    assert v == ascii.ASCIIValue([("foo", "bar"), ("foo", "baz"), ("qux", "quux")])
    assert v == {"foo": ["bar", "baz"], "qux": ["quux"]}
