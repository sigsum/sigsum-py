import io


def dumps(data):
    """
    dumps takes a list of key/values tuples, and serializes it to ASCII.
    If one of the values is not of type str, int or bytes (or a list of those)
    a TypeError is raised.
    """
    res = io.StringIO()
    for [key, values] in data:
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

def parse_line(line, name, count):
    prefix = name + "="
    if not line.startswith(prefix):
        raise ASCIIDecodeError("Expecting '" + prefix+ "' line")
    values = line[len(prefix):].split(" ")
    if len(values) != count:
        raise ASCIIDecodeError(
            "Expecting {} values for '{}' line, got {}".format(count, prefix, len(values)))
    return values

def parse_hash(line, name):
    v = parse_line(line, name, 1)
    h = bytes.fromhex(v[0])
    if len(h) != 32:
        raise ascii.ASCIIDecodeError("invalid length of hex hash value: " + v[0])
    return h

def parse_signature(line, name):
    v = parse_line(line, name, 1)
    h = bytes.fromhex(v[0])
    if len(h) != 64:
        raise ascii.ASCIIDecodeError("invalid length of hex signature value: " + v[0])
    return h

def parse_int(line, name):
    v = parse_line(line, name, 1)
    if len(v[0]) == 0 or len(v[0]) > len(str(1<<63)) or not v[0][0].isdigit():
        raise ascii.ASCIIDecodeError("invalid decimal integer: " + v[0])
    i = int(v[0])
    if i >= (1<<63):
        raise ascii.ASCIIDecodeError("decimal integer too large: " + v[0])
    return i

class ASCIIDecodeError(Exception):
    """
    ASCIIDecodeError indicates that loads couldn't deserialize the given input.
    """
