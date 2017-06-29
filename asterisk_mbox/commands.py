# coding: utf-8
"""Commands used to communicate between client and server."""
CMD_MESSAGE_ERROR = 0
CMD_MESSAGE_LIST = 1
CMD_MESSAGE_PASSWORD = 2
CMD_MESSAGE_MP3 = 3
CMD_MESSAGE_DELETE = 4
CMD_MESSAGE_VERSION = 5


def commandstr(command):
    """Convert command into string."""
    if command == CMD_MESSAGE_ERROR:
        msg = "CMD_MESSAGE_ERROR"
    elif command == CMD_MESSAGE_LIST:
        msg = "CMD_MESSAGE_LIST"
    elif command == CMD_MESSAGE_PASSWORD:
        msg = "CMD_MESSAGE_PASSWORD"
    elif command == CMD_MESSAGE_MP3:
        msg = "CMD_MESSAGE_MP3"
    elif command == CMD_MESSAGE_DELETE:
        msg = "CMD_MESSAGE_DELETE"
    elif command == CMD_MESSAGE_VERSION:
        msg = "CMD_MESSAGE_VERSION"
    else:
        msg = "CMD_MESSAGE_UNKNOWN"
    return msg
