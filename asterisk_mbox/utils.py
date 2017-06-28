"""Utility classes for use in the asterisk_mbox."""

import queue
import os
import socket
import logging
import hashlib

__version__ = "0.3.0"


class PollableQueue(queue.Queue):
    """Queue which allows using select."""

    def __init__(self):
        """Constructor."""
        super().__init__()
        # Create a pair of connected sockets
        if os.name == 'posix':
            self._putsocket, self._getsocket = socket.socketpair()
        else:
            # Compatibility on non-POSIX systems
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            self._putsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._putsocket.connect(server.getsockname())
            self._getsocket, _ = server.accept()
            server.close()

    def fileno(self):
        """fileno."""
        return self._getsocket.fileno()

    def put(self, item, block=True, timeout=None):
        """put."""
        super().put(item, block, timeout)
        self._putsocket.send(b'x')

    def get(self, block=True, timeout=None):
        """get."""
        try:
            item = super().get(block, timeout)
            self._getsocket.recv(1)
            return item
        except queue.Empty:
            raise queue.Empty


def recv_blocking(conn, msglen):
    """Recieve data until msglen bytes have been received."""
    msg = b''
    while len(msg) < msglen:
        maxlen = msglen-len(msg)
        if maxlen > 4096:
            maxlen = 4096
        tmpmsg = conn.recv(maxlen)
        if not tmpmsg:
            raise RuntimeError("socket connection broken")
        msg += tmpmsg
        logging.debug("Msglen: %d of %d", len(msg), msglen)
    logging.debug("Message: %s", msg)
    return msg


def encode_password(password):
    """Hash password and append current asterisk_mbox version."""
    return(hashlib.sha256(password.encode('utf-8')).hexdigest()[:-8] +
           (__version__ + "        ")[:8])


def compare_password(expected, actual):
    """Compare two 64byte encoded passwords."""
    if expected == actual:
        return True, "OK"
    msg = []
    ver_exp = expected[-8:].rstrip()
    ver_act = actual[-8:].rstrip()

    if expected[:-8] != actual[:-8]:
        msg.append("Password mismatch")
    if ver_exp != ver_act:
        msg.append("asterisk_mbox version mismatch.  Client: '" +
                   ver_act + "',  Server: '" + ver_exp + "'")
    return False, ". ".join(msg)
