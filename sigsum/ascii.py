import io


def dumps(data):
    """
    dumps takes a key/values mapping and serializes it to ASCII.
    If one of the values is not of type str, int or bytes (or a list of those)
    a TypeError is raised.
    """
    res = io.StringIO()
    for key in data:
        values = data[key]
        if not isinstance(values, list):
            values = [values]
        for val in values:
            if isinstance(val, (int, str)):
                res.write(f"{key}={val}\n")
            elif isinstance(val, bytes):
                res.write(f"{key}={val.hex()}\n")
            else:
                raise TypeError(
                    f"Object of type {type(val).__name__} is not ASCII serializable"
                )
    res.seek(0)
    return res.read()


def loads(txt):
    """
    loads deserialized the given string into an ASCIIValue.
    """
    kv = []
    for lno, line in enumerate(txt.splitlines(), 1):
        if "=" not in line:
            raise ASCIIDecodeError("Expecting '=' delimiter line 1")
        (key, val) = line.rstrip().split("=", 1)
        if val == "":
            raise ASCIIDecodeError("Expecting value after '=' line 1")
        kv.append((key, val))
    return ASCIIValue(kv)


class ASCIIDecodeError(Exception):
    """
    ASCIIDecodeError indicates that loads couldn't deserialize the given input.
    """


class ASCIIValue:
    """
    ASCIIValue implements Mapping[str, List[str]] with convenience getters to
    parse sigsum types.
    """

    def __init__(self, data):
        self._d = {}
        for k, v in data:
            self._d.setdefault(k, []).append(v)

    def __getitem__(self, k):
        return self._d.__getitem__(k)

    def __len__(self):
        return self._d.__len__()

    def __iter__(self):
        return self._d.__iter__()

    def getone(self, k):
        v = self._d[k]
        if len(v) > 1:
            raise ValueError(f"{k}: expected a single value, got {len(v)}")
        return self._d[k][0]

    def getint(self, k, many=False):
        if many:
            return [int(x) for x in self._d[k]]
        return int(self.getone(k))

    def getbytes(self, k, many=False):
        if many:
            return [bytes.fromhex(x) for x in self._d[k]]
        return bytes.fromhex(self.getone(k))

    def __repr__(self):
        return f'ASCIIValue([{", ".join(f"({k!r}, {v!r})" for k,vs in self._d.items() for v in vs)}])'

    def __eq__(self, other):
        if isinstance(other, ASCIIValue):
            return self._d.__eq__(other._d)
        if isinstance(other, dict):
            return self._d.__eq__(other)
        return NotImplemented
