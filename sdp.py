import utils
import struct
import random

PNP_INFO_SVCLASS_ID = 0x1200
L2CAP_UUID = 0x0100
ATT_UUID = 0x0007
PUBLIC_BROWSE_GROUP_UUID = 0x1002
RFCOMM_UUID = 0x0003
AVCTP_UUID = 0x0017

pack_sdp_pdu_hdr, unpack_sdp_pdu_hdr, sizeof_sdp_pdu_hdr = \
    utils.create_struct_funcs('>', (
        ('pdu_id', 'B', {
            'SDP_SVC_SEARCH_REQ': 0x02,
            'SDP_SVC_SEARCH_RSP': 0x03,
            'SDP_SVC_ATTR_REQ': 0x04,
            'SDP_SVC_ATTR_RSP': 0x05,
            'SDP_SVC_SEARCH_ATTR_REQ': 0x06,
            'SDP_SVC_SEARCH_ATTR_RSP': 0x07,
        }),
        ('tid', 'H'),
        ('plen', 'H'),
    ))

def pack_sdp_pdu(pdu_id, payload, tid=None, plen=None):
    if tid is None:
        tid = random.randint(0, 0xffff)
    if plen is None:
        plen = len(payload)
    hdr = pack_sdp_pdu_hdr(pdu_id=pdu_id, tid=tid, plen=plen)
    return hdr + payload

def unpack_sdp_pdu(data, strict=True):
    hdr_size = sizeof_sdp_pdu_hdr()
    assert len(data) >= hdr_size
    result = unpack_sdp_pdu_hdr(data[:hdr_size])
    if strict:
        assert len(data) == hdr_size + result['plen']
    result['payload'] = data[hdr_size:]
    return result

def pack_seq8(payload):
    assert len(payload) < 0x100
    SDP_SEQ8 = 0x35
    #return bytes([SDP_SEQ8, len(payload)]) + payload
    return ''.join([chr(c) for c in (SDP_SEQ8, len(payload))]) + payload

def pack_uuid16(value):
    assert 0 <= value <= 0xffff
    SDP_UUID16 = 0x19
    return struct.pack('>BH', SDP_UUID16, value)

def pack_uuid32(value):
    assert 0 <= value <= 0xffffffff
    SDP_UUID32 = 0x1A
    return struct.pack('>BI', SDP_UUID32, value)

def pack_uint32(value):
    assert 0 <= value <= 0xffffffff
    SDP_UINT32 = 0x0A
    return struct.pack('>BI', SDP_UINT32, value)

def pack_uint16(value):
    assert 0 <= value <= 0xffff
    SDP_UINT16 = 0x09
    return struct.pack('>BH', SDP_UINT16, value)

def pack_services(services):
    return pack_seq8(b''.join(map(pack_uuid16, services)))

def pack_attribute(attribute):
    if type(attribute) is tuple:
        # Attribute range
        start, end = attribute
        assert 0 <= start <= 0xffff
        assert 0 <= end <= 0xffff
        return pack_uint32(start << 16 | end)
    return pack_uint16(attribute)

def pack_attributes(attributes):
    return pack_seq8(b''.join(map(pack_attribute, attributes)))

def pack_search_attr_request(services, attributes, max_response_size=0xffff, cstate=b''):
    # Need a UUID that we're going to find
    payload = pack_services(services)
    # Max response size
    payload += struct.pack('>H', max_response_size)
    payload += pack_attributes(attributes)
    # State
    payload += chr(len(cstate)) + cstate #bytes([len(cstate)]) + cstate
    return pack_sdp_pdu('SDP_SVC_SEARCH_ATTR_REQ', payload)

def unpack_search_attr_response(response):
    assert len(response) >= 2
    result = {}
    result['len'] = struct.unpack_from('>H', response)[0]
    assert len(response) >= 2 + result['len'] + 1
    result['payload'] = response[2:2 + result['len']]
    cstate_len = response[2 + result['len']]
    result['cstate'] = response[2 + result['len'] + 1:]
    assert len(result['cstate']) == cstate_len
    return result

def pack_search_request(uuid, max_replies = 0xffff, cstate = b''):
    payload = pack_seq8(pack_uuid16(uuid))
    # Max replies, in records (each one is uint32)
    payload += struct.pack('>H', max_replies)
    # State
    payload += chr(len(cstate)) + cstate #bytes([len(cstate)]) + cstate
    a = pack_sdp_pdu('SDP_SVC_SEARCH_REQ', payload)
    return a

def unpack_search_response(response):
    assert len(response) >= 5
    result = {}
    result['total_len'], result['current_len'] = \
        struct.unpack_from('>HH', response)
    result['records'] = struct.unpack_from('>' + ('I' * result['current_len']),
                                           response[4:])
    cstate_len = response[4 + len(result['records']) * 4]
    result['cstate'] = response[4 + len(result['records']) * 4 + 1:]
    assert chr(len(result['cstate'])) == cstate_len
    return result

def do_search_attr_request_full(socket, services, attributes, max_response_size=0xffff):
    cstate = b''
    while True:
        request = pack_search_attr_request(services=services,
                                           attributes=attributes,
                                           max_response_size=max_response_size,
                                           cstate=cstate)
        socket.send(request)
        response = unpack_sdp_pdu(socket.recv(4096))
        response['payload'] = unpack_search_attr_response(response['payload'])
        cstate = response['payload']['cstate']
        yield (request, response)
        if cstate == b'':
            break

