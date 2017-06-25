""" asteriskvm_client.py -- Do stuff"""

import sys
import socket
import select
import json
import time
import hashlib
import configparser

from threading import Thread
from asteriskvm.utils import PollableQueue, recv_blocking

import asteriskvm.commands as cmd


def build_request(request):
    """Build message to transfer over the socket from a request"""
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
    print(msg)
    print(len(msg))
    return msg

class Client:
    """asteriskvm client"""
    def __init__(self, ipaddr, port, password):
        """constructor"""
        self.ipaddr = ipaddr
        self.port = port
        self.password = password
        self.soc = None
        # Send data to the server
        self.request_queue = PollableQueue()
        # Receive data from the server
        self.result_queue = PollableQueue()
        self.connect()
        self.thread = Thread(target=self.loop)
        self.thread.setDaemon(True)
        self.thread.start()

    def connect(self):
        """connect to server"""
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.soc.connect((self.ipaddr, self.port))
                break
            except ConnectionRefusedError:
                print("Connection Refused")
                time.sleep(5)
        self.soc.send(build_request({'cmd': cmd.CMD_MESSAGE_PASSWORD, 'sha': self.password}))

    def recv_msg(self):
        """Read a message from the server"""
        command = ord(recv_blocking(self.soc, 1))
        msglen = recv_blocking(self.soc, 4)
        msglen = (msglen[0] << 24) + (msglen[1] << 16) + (msglen[2] << 8) + msglen[3]
        msg = recv_blocking(self.soc, msglen)
        return command, msg

    # pylint: disable=too-many-branches
    def loop(self):
        """Polling loop"""
        request = {}
        status = {}
        self.soc.send(build_request({'cmd': cmd.CMD_MESSAGE_LIST}))
        while not status:
            try:
                command, msg = self.recv_msg()
            except RuntimeError:
                print("Lost connection")
                self.connect()
                continue
            if command == cmd.CMD_MESSAGE_LIST:
                status = json.loads(msg.decode('utf-8'))
        while True:
            readable, dummy_writable, dummy_errored = select.select([self.soc,
                                                                     self.request_queue], [], [])
            if self.soc in readable:
                # We have incoming data
                try:
                    command, msg = self.recv_msg()
                except RuntimeError:
                    print("Lost connection")
                    self.connect()
                    continue
                if command == cmd.CMD_MESSAGE_LIST:
                    print("Got CMD_MESSAGE_LIST")
                    status = json.loads(msg.decode('utf-8'))
                    if request and request['cmd'] == cmd.CMD_MESSAGE_LIST:
                        if self.result_queue:
                            self.result_queue.put(status)
                        request = {}
                elif command == cmd.CMD_MESSAGE_MP3:
                    print("Got CMD_MESSAGE_MP3")
                    if request and request['cmd'] == cmd.CMD_MESSAGE_MP3:
                        if self.result_queue:
                            self.result_queue.put(msg)
                        request = {}

            if self.request_queue in readable:
                request = self.request_queue.get()
                self.request_queue.task_done()
                if request['cmd'] == cmd.CMD_MESSAGE_LIST:
                    if self.result_queue:
                        self.result_queue.put(status)
                    request = {}
                else:
                    self.soc.send(build_request(request))

    def messages(self):
        """How many messages are available"""
        self.request_queue.put({'cmd': cmd.CMD_MESSAGE_LIST})
        return self.result_queue.get()

    def num_messages(self):
        """How many messages are available"""
        status = self.messages()
        return len(status.keys())

    def mp3(self, sha):
        """How many messages are available"""
        self.request_queue.put({'cmd': cmd.CMD_MESSAGE_MP3, 'sha': sha})
        return self.result_queue.get()

def main():
    """Main thread"""

    if len(sys.argv) != 2:
        print("Must specify configuration file")
        sys.exit()
    config = configparser.ConfigParser()
    config.read(sys.argv[1])

    password = config.get('default', 'password')
    password = hashlib.sha256(password.encode('utf-8')).hexdigest().encode('utf-8')
    client = Client(config.get('default', 'host'), config.getint('default', 'port'), password)
    status = client.messages()
    key = list(status.keys())[0]
    print(key)
    print(client.mp3(status[key]['sha'].encode('utf-8')))
    while True:
        continue

if __name__ == '__main__':
    main()
