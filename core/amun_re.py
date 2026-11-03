r"""
[Amun - low interaction honeypot]
re wrapper for the Python 3 port (amun-nx): str patterns are compiled with
re.ASCII so that \w, \d and \s match exactly what they matched on Python 2
byte strings (Amun handles network data as latin-1 str, see amun_compat.py).
"""

import re as _re
from re import *  # noqa: F401,F403


def compile(pattern, flags=0):
    if isinstance(pattern, str):
        flags |= _re.ASCII
    return _re.compile(pattern, flags)
