#!/usr/bin/python3
"""Loopback-test proxy: let OpenSSH create a file, then drop its HANDLE reply."""
import struct
import subprocess
import sys


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


def packet(stream):
    header = read_exact(stream, 4)
    length = struct.unpack(">I", header)[0]
    if not 1 <= length <= 1024 * 1024:
        raise ValueError("unexpected test packet size")
    return header + read_exact(stream, length)


server = subprocess.Popen(
    ["/usr/lib/openssh/sftp-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
)
try:
    while True:
        request = packet(sys.stdin.buffer)
        server.stdin.write(request)
        server.stdin.flush()
        response = packet(server.stdout)
        # SSH_FXP_OPEN (3) succeeded with SSH_FXP_HANDLE (102). Close the
        # channel without returning that response, leaving creation unconfirmed.
        if request[4] == 3 and response[4] == 102:
            break
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
except EOFError:
    pass
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
