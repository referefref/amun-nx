"""
[Amun - low interaction honeypot]
struct wrapper for the Python 3 port (amun-nx): pack() returns, and unpack()
accepts, latin-1 str (one character per byte) as Python 2's struct did with
byte strings.  See amun_compat.py.
"""

import struct as _struct
from struct import error, calcsize

from amun_compat import to_bytes, to_str


def _arg(a):
    if isinstance(a, str):
        return to_bytes(a)
    if isinstance(a, float):
        # Python 2's struct truncated floats passed to integer formats
        # (Amun packs SMB/NTP-style timestamps this way); Amun uses no float formats
        return int(a)
    return a


def pack(fmt, *args):
    args = tuple(_arg(a) for a in args)
    return to_str(_struct.pack(fmt, *args))


def unpack(fmt, data):
    return tuple(to_str(v) if isinstance(v, bytes) else v for v in _struct.unpack(fmt, to_bytes(data)))


def unpack_from(fmt, data, offset=0):
    return tuple(to_str(v) if isinstance(v, bytes) else v for v in _struct.unpack_from(fmt, to_bytes(data), offset))
