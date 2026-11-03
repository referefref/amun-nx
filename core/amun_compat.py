"""
[Amun - low interaction honeypot]
Python 3 compatibility layer (amun-nx)

Amun was written for Python 2, where network data, shellcode and file
contents are all byte strings ("str").  The Python 3 port keeps that model:
everything Amun receives is decoded as ISO-8859-1 (latin-1), which maps each
byte to exactly one character, and everything it sends or stores is encoded
back the same way.  The vulnerability modules and the shellcode manager can
therefore keep working on str objects exactly as before, byte for byte.

Importing this module installs the conversion at the socket layer used by
asyncore/asynchat.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
"""

import asyncore
import asynchat
import socket

ENCODING = 'latin-1'


def to_bytes(data):
    """str (one character per byte) -> bytes; bytes are passed through"""
    if isinstance(data, str):
        return data.encode(ENCODING)
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return data


def to_str(data):
    """bytes -> str with one character per byte; str is passed through"""
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).decode(ENCODING)
    return data


class L1Socket(object):
    """Wraps a socket so that send/recv work on latin-1 str as in Python 2"""

    def __init__(self, sock):
        self.__dict__['_sock'] = sock

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def __setattr__(self, name, value):
        setattr(self._sock, name, value)

    def __repr__(self):
        return '<L1Socket %r>' % (self._sock,)

    def fileno(self):
        return self._sock.fileno()

    def send(self, data, *args):
        return self._sock.send(to_bytes(data), *args)

    def sendall(self, data, *args):
        return self._sock.sendall(to_bytes(data), *args)

    def sendto(self, data, *args):
        return self._sock.sendto(to_bytes(data), *args)

    def recv(self, *args):
        return to_str(self._sock.recv(*args))

    def recvfrom(self, *args):
        data, addr = self._sock.recvfrom(*args)
        return to_str(data), addr

    def accept(self):
        conn, addr = self._sock.accept()
        return L1Socket(conn), addr


def wrap(sock):
    if sock is None or isinstance(sock, L1Socket):
        return sock
    return L1Socket(sock)


_orig_set_socket = asyncore.dispatcher.set_socket


def _set_socket(self, sock, map=None):
    return _orig_set_socket(self, wrap(sock), map)


asyncore.dispatcher.set_socket = _set_socket

_orig_dispatcher_init = asyncore.dispatcher.__init__


def _dispatcher_init(self, sock=None, map=None):
    return _orig_dispatcher_init(self, wrap(sock), map)


asyncore.dispatcher.__init__ = _dispatcher_init

_orig_push = asynchat.async_chat.push


def _push(self, data):
    return _orig_push(self, to_bytes(data))


asynchat.async_chat.push = _push

_orig_recv = asyncore.dispatcher.recv


def _recv(self, buffer_size):
    # asyncore returns the literal b'' on EOF or a reset connection
    return to_str(_orig_recv(self, buffer_size))


asyncore.dispatcher.recv = _recv
