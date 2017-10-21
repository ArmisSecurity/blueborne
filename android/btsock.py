import socket
import utils

# /usr/include/bluetooth/bluetooth.h and /usr/include/bluetooth/l2cap.h
SOL_L2CAP = 6
L2CAP_OPTIONS = 1

_pack_l2cap_options, _unpack_l2cap_options, _sizeof_l2cap_options = \
    utils.create_struct_funcs('', (
        ('omtu', 'H'),
        ('imtu', 'H'),
        ('flush_to', 'H'),
        ('mode', 'B'),
        ('fcs', 'B'),
        ('max_tx', 'B'),
        ('txwin_size', 'H'),
    ))

def l2cap_connect(dst, src=None, mtu=None):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    if src is not None:
        sock.bind(src)
    if mtu is not None:
        set_imtu(sock, mtu)
    sock.connect(dst)
    return sock

def get_l2cap_options(sock):
    return _unpack_l2cap_options(sock.getsockopt(SOL_L2CAP, L2CAP_OPTIONS,
                                                 _sizeof_l2cap_options()))

def set_l2cap_options(sock, options):
    value = _pack_l2cap_options(**options)
    sock.setsockopt(SOL_L2CAP, L2CAP_OPTIONS, value)

def get_imtu(sock):
    return get_l2cap_options(sock)['imtu']

def set_imtu(sock, imtu):
    options = get_l2cap_options(sock)
    options['imtu'] = imtu
    set_l2cap_options(sock, options)

