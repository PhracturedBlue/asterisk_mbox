"""asterisk_mbox_client: Client API for Asterisk Mailboxes."""

import sys
import socket
import select
import json
import configparser
import logging

import queue
import threading

from asterisk_mbox.utils import PollableQueue, recv_blocking, encode_password

import asterisk_mbox.commands as cmd


class ServerError(Exception):
    """Server reported an error during synchronous tranfer."""
    pass


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
    """Ensure data is type 'bytes'."""
    if isinstance(data, str):
        return data.encode('utf-8')
    return data


class Client:
    """asterisk_mbox client."""

    def __init__(self, ipaddr, port, password, callback=None, **kwargs):
        """constructor."""
        self._ipaddr = ipaddr
        self._port = port
        self._password = encode_password(password).encode('utf-8')
        self._callback = callback
        self._soc = None
        self._thread = None
        self._status = {}

        # Stop thread
        self.signal = PollableQueue()
        # Send data to the server
        self.request_queue = PollableQueue()
        # Receive data from the server
        self.result_queue = PollableQueue()
        if 'autostart' not in kwargs or kwargs['autostart']:
            self.start()

    def start(self):
        """Start thread."""
        if not self._thread:
            logging.info("Starting asterisk mbox thread")
            # Ensure signal queue is empty
            try:
                while True:
                    self.signal.get(False)
            except queue.Empty:
                pass
            self._thread = threading.Thread(target=self._loop)
            self._thread.setDaemon(True)
            self._thread.start()

    def stop(self):
        """Stop thread."""
        if self._thread:
            self.signal.put("Stop")
            self._thread.join()
            if self._soc:
                self._soc.shutdown()
                self._soc.close()
            self._thread = None

    def _connect(self):
        """Connect to server."""
        self._soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._soc.connect((self._ipaddr, self._port))
        self._soc.send(_build_request({'cmd': cmd.CMD_MESSAGE_PASSWORD,
                                       'sha': self._password}))

    def _recv_msg(self):
        """Read a message from the server."""
        command = ord(recv_blocking(self._soc, 1))
        msglen = recv_blocking(self._soc, 4)
        msglen = ((msglen[0] << 24) + (msglen[1] << 16) +
                  (msglen[2] << 8) + msglen[3])
        msg = recv_blocking(self._soc, msglen)
        return command, msg

    def _handle_msg(self, command, msg, request):
        if command == cmd.CMD_MESSAGE_ERROR:
            logging.warning("Received error: %s", msg.decode('utf-8'))
        elif command == cmd.CMD_MESSAGE_LIST:
            self._status = json.loads(msg.decode('utf-8'))
            msg = self._status

        if self._callback and 'sync' not in request:
            self._callback(command, msg)
        elif request and (command == request.get('cmd') or
                          command == cmd.CMD_MESSAGE_ERROR):
            logging.debug("Got command: %s", cmd.commandstr(command))
            self.result_queue.put([command, msg])
            request.clear()
        else:
            logging.debug("Got unhandled command: %s",
                          cmd.commandstr(command))

    def _clear_request(self, request):
        if not self._callback or 'sync' in request:
            self.result_queue.put(
                [cmd.CMD_MESSAGE_ERROR, "Not connected to server"])
        request.clear()

    def _loop(self):
        """Handle data."""
        request = {}
        connected = False
        while True:
            timeout = None
            sockets = [self.request_queue, self.signal]
            if not connected:
                try:
                    self._clear_request(request)
                    self._connect()
                    self._soc.send(_build_request(
                        {'cmd': cmd.CMD_MESSAGE_LIST}))
                    connected = True
                except ConnectionRefusedError:
                    timeout = 5.0
            if connected:
                sockets.append(self._soc)

            readable, _writable, _errored = select.select(
                sockets, [], [], timeout)

            if self.signal in readable:
                break

            if self._soc in readable:
                # We have incoming data
                try:
                    command, msg = self._recv_msg()
                    self._handle_msg(command, msg, request)
                except (RuntimeError, ConnectionResetError):
                    logging.warning("Lost connection")
                    connected = False
                    self._clear_request(request)

            if self.request_queue in readable:
                request = self.request_queue.get()
                self.request_queue.task_done()
                if not connected:
                    self._clear_request(request)
                else:
                    if (request['cmd'] == cmd.CMD_MESSAGE_LIST and
                            self._status and
                            (not self._callback or 'sync' in request)):
                        self.result_queue.put(
                            [cmd.CMD_MESSAGE_LIST, self._status])
                        request = {}
                    else:
                        self._soc.send(_build_request(request))

    def _queue_msg(self, item, **kwargs):
        if not self._thread:
            raise ServerError("Client not running")
        if not self._callback or kwargs.get('sync'):
            item['sync'] = True
            self.request_queue.put(item)
            command, msg = self.result_queue.get()
            if command == cmd.CMD_MESSAGE_ERROR:
                raise ServerError(msg)
            return msg
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
        """Delete a message."""
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
