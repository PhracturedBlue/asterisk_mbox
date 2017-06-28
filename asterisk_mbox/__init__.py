"""asterisk_mbox_client: Client API for Asterisk Mailboxes."""

import sys
import socket
import select
import json
import configparser
import logging

import threading

from asterisk_mbox.utils import PollableQueue, recv_blocking, encode_password

import asterisk_mbox.commands as cmd


def _build_request(request):
    """Build message to transfer over the socket from a request."""
    msg = bytes([request['cmd']])
    if 'dest' in request:
        msg += bytes([request['dest']])
    else:
        msg += b'\0'
    if 'sha' in request:
        msg += request['sha']
    else:
        for dummy in range(64):
            msg += b'0'
    logging.debug("Request (%d): %s", len(msg), msg)
    return msg


def _get_bytes(data):
    """Ensdure data is type 'bytes'."""
    if isinstance(data, str):
        return data.encode('utf-8')
    return data


class Client:
    """asterisk_mbox client."""

    def __init__(self, ipaddr, port, password, callback=None, **kwargs):
        """constructor."""
        self.ipaddr = ipaddr
        self.port = port
        self.password = encode_password(password).encode('utf-8')
        self.callback = callback
        self.soc = None
        self.signal = threading.Event()
        self.signal.set()

        # Send data to the server
        self.request_queue = PollableQueue()
        # Receive data from the server
        self.result_queue = PollableQueue()
        if 'autostart' not in kwargs or kwargs['autostart']:
            self.start()

    def start(self):
        """Start thread."""
        if self.signal.is_set():
            logging.info("Starting asterisk mbox thread")
            self.signal.clear()
            self._connect()
            self.thread = threading.Thread(target=self.loop)
            self.thread.setDaemon(True)
            self.thread.start()

    def stop(self):
        """Stop thread."""
        self.signal.set()
        self.thread.join()
        self.soc.shutdown()
        self.soc.close()

    def _connect(self):
        """Connect to server."""
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while not self.signal.is_set():
            try:
                self.soc.connect((self.ipaddr, self.port))
                self.soc.send(_build_request({'cmd': cmd.CMD_MESSAGE_PASSWORD,
                                              'sha': self.password}))
                break
            except ConnectionRefusedError:
                logging.warning("Connection Refused")
                self.signal.wait(5.0)

    def _recv_msg(self):
        """Read a message from the server."""
        command = ord(recv_blocking(self.soc, 1))
        msglen = recv_blocking(self.soc, 4)
        msglen = ((msglen[0] << 24) + (msglen[1] << 16) +
                  (msglen[2] << 8) + msglen[3])
        msg = recv_blocking(self.soc, msglen)
        return command, msg

    # pylint: disable=too-many-branches
    def loop(self):
        """Handle data."""
        request = {}
        status = {}
        self.soc.send(_build_request({'cmd': cmd.CMD_MESSAGE_LIST}))
        while not self.signal.is_set():
            readable, _writable, _errored = select.select([self.soc,
                                                           self.request_queue],
                                                          [], [])
            if self.soc in readable:
                # We have incoming data
                try:
                    command, msg = self._recv_msg()
                except (RuntimeError, ConnectionResetError):
                    logging.warning("Lost connection")
                    self._connect()
                    continue
                if command == cmd.CMD_MESSAGE_PASSWORD:
                    logging.warning("Bad password: %s", msg.decode('utf-8'))
                if self.callback and command != cmd.CMD_MESSAGE_MP3:
                    if command == cmd.CMD_MESSAGE_LIST:
                        msg = json.loads(msg.decode('utf-8'))
                    self.callback(command, msg)
                else:
                    if command == cmd.CMD_MESSAGE_LIST:
                        logging.debug("Got CMD_MESSAGE_LIST")
                        status = json.loads(msg.decode('utf-8'))
                        if request and request['cmd'] == cmd.CMD_MESSAGE_LIST:
                            self.result_queue.put(status)
                            request = {}
                    elif command == cmd.CMD_MESSAGE_MP3:
                        logging.debug("Got CMD_MESSAGE_MP3")
                        if request and request['cmd'] == cmd.CMD_MESSAGE_MP3:
                            self.result_queue.put(msg)
                            request = {}
                    elif command == cmd.CMD_MESSAGE_DELETE:
                        logging.debug("Got CMD_MESSAGE_DELETE")
                        if (request and
                                request['cmd'] == cmd.CMD_MESSAGE_DELETE):
                            self.result_queue.put(msg)
                            request = {}

            if self.request_queue in readable:
                request = self.request_queue.get()
                self.request_queue.task_done()
                if (request['cmd'] == cmd.CMD_MESSAGE_LIST and
                        not self.callback and status):
                    self.result_queue.put(status)
                    request = {}
                else:
                    self.soc.send(_build_request(request))

    def _queue_msg(self, item, **kwargs):
        if not self.callback or kwargs.get('sync'):
            item['sync'] = True
            self.request_queue.put(item)
            return self.result_queue.get()
        else:
            self.request_queue.put(item)

    def messages(self, **kwargs):
        """Get list of messages with metadata."""
        return self._queue_msg({'cmd': cmd.CMD_MESSAGE_LIST}, **kwargs)

    def mp3(self, sha, **kwargs):
        """Get raw MP3 of a message."""
        return self._queue_msg({'cmd': cmd.CMD_MESSAGE_MP3,
                                'sha': _get_bytes(sha)}, **kwargs)

    def delete(self, sha, **kwargs):
        """How many messages are available."""
        return self._queue_msg({'cmd': cmd.CMD_MESSAGE_DELETE,
                                'sha': _get_bytes(sha)}, **kwargs)


def _callback(command, message):
    logging.debug("Async: %d: %s", command, message)


def main():
    """Show example using the API."""
    __async__ = True
    logging.basicConfig(format="%(levelname)-10s %(message)s",
                        level=logging.DEBUG)

    if len(sys.argv) != 2:
        logging.error("Must specify configuration file")
        sys.exit()
    config = configparser.ConfigParser()
    config.read(sys.argv[1])

    password = config.get('default', 'password')
    if __async__:
        client = Client(config.get('default', 'host'),
                        config.getint('default', 'port'), password, _callback)
    else:
        client = Client(config.get('default', 'host'),
                        config.getint('default', 'port'),
                        password)
        status = client.messages()
        msg = status[0]
        print(msg)
        print(client.mp3(msg['sha'].encode('utf-8')))
    while True:
        continue


if __name__ == '__main__':
    main()
