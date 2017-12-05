import sys
from scapy.layers.bluetooth import *
import binascii
from traced_bt_user_sock import BluetoothUserSocket_WithTrace

# TODO: Allocate scid dynamically (currently it is hard coded to OUR_LOCAL_SCID)
OUR_LOCAL_SCID = 0x40

def hci_devid(dev):
    # Replacement to bluez's hci_devid because we don't care if the interface is
    # down
    if not dev.startswith('hci'):
        raise ValueError()
    if not dev[3:].isdigit():
        raise ValueError()
    return int(dev[3:])

# Hack around bad definitions in scapy
def unbind_layers(lower, upper):
    lower.payload_guess = [(fval, pay) for (fval, pay) in lower.payload_guess if
        pay is not upper]
    lower.payload_guess.append((fval, upper))

unbind_layers(HCI_Event_Hdr, HCI_Event_Number_Of_Completed_Packets)

def to_opcode(ogf, ocf):
    return (ogf << 10) | ocf

class HCI_Cmd_Create_Connection(Packet):
    name = "Create Connection"
    fields_desc = [ LEMACField("bd_addr", None),
                    LEShortField("packet_type", 0xcc18),
                    ByteEnumField("page_scan_repetition_mode", 2,
                                  {0: "R0", 1: "R1", 2: "R2"}),
                    ByteField("reserved", 0),
                    LEShortField("clock_offset", 0),
                    ByteEnumField("allow_role_switch", 0,
                                  {0: "no", 1: "yes"}), ]

class HCI_Event_Connection_Complete(Packet):
    name = "Connection Complete"
    fields_desc = [ ByteEnumField("status", 0, {0:"success"}),
                    XLEShortField("connection_handle", 0),
                    LEMACField("bd_addr", None),
                    ByteEnumField("link_type", 1,
                                  {0: "sco", 1: "acl"}),
                    ByteEnumField("encryption_enabled", 0,
                                  {0: "disabled", 1: "enabled"}), ]

class HCI_Cmd_Read_Remote_Supported_Features(Packet):
    name = "Read Remote Supported Features"
    fields_desc = [ XLEShortField("connection_handle", 0), ]

class HCI_Event_Read_Remote_Supported_Features_Complete(Packet):
    name = "Read Remote Supported Features Complete"
    fields_desc = [ ByteEnumField("status", 0, {0: "success"}),
                    XLEShortField("connection_handle", 0),
                    StrFixedLenField("lmp_features", '\x00' * 8, 8), ]

class HCI_Event_Number_Of_Completed_Packets(Packet):
    name = "Number Of Completed Packets"
    fields_desc = [ ByteField("number_of_handles", 0),
                    FieldListField("connection_handle", [],
                                   XLEShortField("", 0),
                                   count_from=lambda pkt: pkt.number_of_handles),
                    FieldListField("hc_num_of_completed_packets", [],
                                   XLEShortField("", 0),
                                   count_from=lambda pkt: pkt.number_of_handles),
                  ]

bind_layers(HCI_Command_Hdr, HCI_Cmd_Create_Connection,
            opcode=to_opcode(0x01, 0x0005))
bind_layers(HCI_Event_Hdr, HCI_Event_Connection_Complete, code=0x03)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Remote_Supported_Features,
            opcode=to_opcode(0x01, 0x001b))
bind_layers(HCI_Event_Hdr, HCI_Event_Read_Remote_Supported_Features_Complete,
            code=0x0b)
bind_layers(HCI_Event_Hdr, HCI_Event_Number_Of_Completed_Packets, code=0x13)

class Loop(object):
    def __init__(self, sock):
        self._sock = sock
        self._waiters = {}

    def on(self, condition, handler):
        if handler is None:
            handler = lambda loop, packet: None
        if condition not in self._waiters:
            self._waiters[condition] = []
        self._waiters[condition].append(handler)

    def on_pkt(self, layer, handler):
        self.on(lambda packet: packet is not None and layer in packet, handler)

    def ignore(self, condition):
        self.on(condition, None)

    def ignore_pkt(self, layer):
        return self.on_pkt(layer, None)

    def _build_queue(self, packet):
        result = []
        for condition in self._waiters.keys():
            if not condition(packet):
                continue
            result.extend(self._waiters[condition])
            del self._waiters[condition]
        return result

    def _iterate_with_packet(self, packet):
        queue = self._build_queue(packet)
        if len(queue) == 0:
            print 'WARNING: ignored packet %s' % (repr(packet), )
            return []
        results = []
        while len(queue) != 0:
            results.extend([handler(self, packet) for handler in queue])
            queue = self._build_queue(None)
        return filter(lambda x: x is not None, results)

    def iterate(self):
        packet = self._sock.recv()
        # print('<< %s' % (repr(packet), ))
        return self._iterate_with_packet(packet)

    def is_waiting(self):
        return len(self._waiters) != 0

    def cont(self):
        while self.is_waiting():
            results = self.iterate()
            if len(results) != 0:
                return results
        return []

    def finish(self):
        while self.is_waiting():
            self.iterate()

    def send(self, packet):
        # print('>> %s' % (repr(packet), ))
        self._sock.send(packet)

L2CAP_DEFAULT_MTU = 672

class L2CAP(object):
    def __init__(self, loop, handle):
        self._loop = loop
        self._total_length = None
        self._data = ''
        self._handle = handle
        self._queue = []
        self._call_on_data()
        self.drop_acl_mode = False

    def _unpack_packet_handle_and_flags(self, packet):
        assert HCI_ACL_Hdr in packet
        # HCI_ACL_Hdr definition in scapy is wrong; don't have time to fix it
        packet_handle  = (packet[HCI_ACL_Hdr].flags & 0x0f) << 8
        packet_handle |= packet[HCI_ACL_Hdr].handle
        packet_flags = packet[HCI_ACL_Hdr].flags >> 4
        return packet_handle, packet_flags

    def _is_relevant(self, packet):
        if packet is None:
            return False
        if HCI_ACL_Hdr not in packet:
            return False
        if self.drop_acl_mode:
            return False
        packet_handle, packet_flags = self._unpack_packet_handle_and_flags(packet)
        return self._handle == packet_handle

    def _flush(self):
        data = self._data
        assert len(data) == self._total_length
        self._data = ''
        self._total_length = None
        self._queue.append(L2CAP_Hdr(data))

    def _handle_acl(self, loop, packet):
        assert not self.drop_acl_mode
        self._call_on_data()
        packet_handle, packet_flags = self._unpack_packet_handle_and_flags(packet)
        if self._total_length is None:
            self._total_length = packet[HCI_ACL_Hdr].len
        else:
            assert packet_flags & 0x02 == 0x02, "Expected continuation packet"
        self._data += str(packet[HCI_ACL_Hdr].payload)
        if len(self._data) < self._total_length:
            return None
        self._flush()
        return True

    def _call_on_data(self):
        self._loop.on(self._is_relevant, self._handle_acl)

    def recv(self):
        while len(self._queue) == 0:
            assert self._loop.cont() == [True]
        return self._queue.pop(0)

    def _verify_sent(self, _, packet):
        index = packet[HCI_Event_Number_Of_Completed_Packets].connection_handle.index(self._handle)
        return ('send_ack', packet[HCI_Event_Number_Of_Completed_Packets].hc_num_of_completed_packets[index])

    def send(self, l2cap):
        # Here we perform ACL fragmentation.
        # For simplicity we chose to split the fragments based on the L2CAP_DEFAULT_MTU,
        # However, the correct way to do it is by using the specific controller's mtu limitations
        # and\or the currently negotiated MTU of the connection.
        for i in range(0, len(str(l2cap)), L2CAP_DEFAULT_MTU):
            self.send_fragment(Raw(str(l2cap)[i:i+L2CAP_DEFAULT_MTU]), i == 0)

    def send_fragment(self, frag, is_first):
        flags = 0
        if not is_first:
            flags |= 1
        # HCI_ACL_Hdr is a piece of shit, also see rant above
        scapy_handle = self._handle & 0xff
        scapy_flags = self._handle >> 8 | ((flags & 0x0f) << 4)

        hci = HCI_Hdr() / HCI_ACL_Hdr(handle=scapy_handle, flags=scapy_flags) / frag
        self._loop.on(lambda pkt: (pkt is not None and
                                   HCI_Event_Number_Of_Completed_Packets in pkt and
                                   self._handle in pkt.connection_handle),
                      self._verify_sent)
        self._loop.send(hci)
        while True:
            result = self._loop.cont()
            if result == [True]:
                continue
            break
        assert result == [('send_ack', True)]

def is_complete_evt_for_cmd(cmd, event):
    if event is None:
        return False
    if HCI_Event_Command_Complete not in event:
        return False
    if event.code != 0x0e:
        return False
    if event.opcode != cmd.opcode:
        return False
    return True

def is_pending_evt_for_cmd(cmd, event):
    if event is None:
        return False
    if HCI_Event_Command_Status not in event:
        return False
    if event.code != 0x0f:
        return False
    if event.opcode != cmd.opcode:
        return False
    return event.status == 0

def reset(loop):
    cmd = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Reset()
    loop.on(lambda evt: is_complete_evt_for_cmd(cmd, evt),
            lambda loop, evt: evt.status == 0)
    loop.send(cmd)
    assert loop.cont() == [True]

def acl_connect(loop, addr):
    cmd = HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_Create_Connection(bd_addr=addr)
    loop.ignore(lambda evt: is_pending_evt_for_cmd(cmd, evt))
    loop.on_pkt(HCI_Event_Connection_Complete,
                lambda loop, evt: evt[HCI_Event_Connection_Complete])
    loop.send(cmd)
    result = loop.cont()
    
    assert len(result) == 1
    result = result[0]
    return result.status == 0, result.connection_handle

def ignore_evt(loop, code):
    loop.ignore(lambda evt: evt is not None and HCI_Event_Hdr in evt and evt.code == code)

def read_remote_supported_features(loop, handle):
    cmd = (HCI_Hdr() / HCI_Command_Hdr() /
           HCI_Cmd_Read_Remote_Supported_Features(connection_handle=handle))
    loop.ignore(lambda evt: is_pending_evt_for_cmd(cmd, evt))
    loop.ignore_pkt(HCI_Event_Read_Remote_Supported_Features_Complete)
    loop.send(cmd)

def is_info_req(info_req):
    return info_req is not None and L2CAP_InfoReq in info_req

def is_info_req_features(info_req):
    return is_info_req(info_req) and info_req.type == 2

def is_info_rsp(pkt):
    return pkt is not None and L2CAP_InfoResp in pkt

def is_info_rsp_features(pkt):
    return is_info_rsp(pkt) and pkt.id == 1 and pkt.type == 2

def is_info_rsp_fixed_channels(pkt):
    return is_info_rsp(pkt) and pkt.id == 1 and pkt.type == 3

def is_info_req_fixed_channels(info_req):
    return is_info_req(info_req) and info_req.type == 3

def reply_to_info_req_features(loop, info_req):
    features = binascii.unhexlify('b8020000')
    resp = (L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=info_req.id) /
            L2CAP_InfoResp(type=2, result=0, data=features))
    loop.send(resp)
    return True

def reply_to_info_req_fixed_channels(loop, info_req):
    features = binascii.unhexlify('0600000000000000')
    resp = (L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=info_req.id) /
            L2CAP_InfoResp(type=3, result=0, data=features))
    loop.send(resp)
    return True

def send_info_req_features(loop):
    info_req = L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=1) / L2CAP_InfoReq(type=2)
    loop.on(lambda pkt: pkt is not None and
                        L2CAP_InfoResp in pkt and
                        pkt.id == 1 and
                        pkt.type == 2,
            lambda loop, pkt: True)
    loop.send(info_req)
    assert loop.cont() == [True]

def send_info_req_fixed_channels(loop):
    info_req = L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=1) / L2CAP_InfoReq(type=3)
    loop.on(lambda pkt: pkt is not None and
                        L2CAP_InfoResp in pkt and
                        pkt.id == 1 and
                        pkt.type == 3,
            lambda loop, pkt: True)
    loop.send(info_req)
    assert loop.cont() == [True]

def l2cap_connect(loop, psm='SDP', scid=OUR_LOCAL_SCID):
    connect_req = (L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=1) /
                   L2CAP_ConnReq(psm=psm, scid=scid))
    loop.on_pkt(L2CAP_ConnResp,
                lambda loop, pkt: pkt)
    loop.send(connect_req)
    result = loop.cont()
    assert len(result) == 1
    connect_resp = result[0]
    assert L2CAP_ConnResp in connect_resp
    assert connect_resp.id == 1
    assert connect_resp.scid == scid
    assert connect_resp.status == 0
    return connect_resp.dcid

def reply_to_conf_req_unaccept(loop, scid, dcid):
    loop.on(lambda conf_req: conf_req is not None and
                             L2CAP_ConfReq in conf_req and
                             conf_req.dcid == scid,
            lambda loop, conf_req: loop.send(L2CAP_Hdr(cid=1) /
                                             L2CAP_CmdHdr(id=conf_req.id) /
                                             L2CAP_ConfResp(scid=dcid, flags=0, result='unaccept') /
                                             Raw(binascii.unhexlify('01020002'))) or True)
    assert loop.cont() == [True]

def reply_to_conf_req_accept(loop, scid, dcid):
    # We agree to any configuration requested by the other peer.
    loop.on(lambda conf_req: conf_req is not None and
                             L2CAP_ConfReq in conf_req and
                             conf_req.dcid == scid,
            lambda loop, conf_req: loop.send(L2CAP_Hdr(cid=1) /
                                             L2CAP_CmdHdr(id=conf_req.id) /
                                             L2CAP_ConfResp(scid=dcid, flags=0, result='success')))

# Do the lockstep confiugration process (with EFS) - only with targets which supports this.
def lockstep_efs_conf_process(loop, scid, dcid):
    # Note that stype == L2CAP_SERV_NOTRAFIC (0) which is important
    efs = binascii.unhexlify('0610') + (binascii.unhexlify('00') * 0x10)
    conf_req = (L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=1) /
                L2CAP_ConfReq(dcid=dcid, flags=0) /
                Raw(binascii.unhexlify('0409000000000000000000') + efs))
    loop.on(lambda conf_resp: conf_resp is not None and
                              conf_resp.id == 1 and
                              L2CAP_ConfResp in conf_resp and
                              conf_resp.scid == scid and
                              conf_resp.result == 4, # pending
            lambda loop, conf_resp: conf_resp)
    loop.send(conf_req)
    conf_resp = loop.cont()[0]

    resp = (L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=conf_req.id) /
            L2CAP_ConfResp(scid=dcid, flags=0, result=4) /
            Raw(binascii.unhexlify('01020004')))
    loop.on(lambda conf_resp: conf_resp is not None and
                              conf_resp.id == 1 and
                              L2CAP_ConfResp in conf_resp and
                              conf_resp.scid == scid and
                              conf_resp.result == 0,
            lambda loop, conf_resp: conf_resp)
    loop.send(resp)
    conf_resp = loop.cont()[0]
    resp = (L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=conf_req.id) /
            L2CAP_ConfResp(scid=dcid, flags=0, result=0))
    loop.send(resp)

# Do the standard configuration process
def standard_conf_process(loop, scid, dcid):
    conf_req = (L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=1) /
                L2CAP_ConfReq(dcid=dcid, flags=0) /
                Raw(binascii.unhexlify('0102a002')))
    loop.on(lambda conf_resp: conf_resp is not None and
                              conf_resp.id == 1 and
                              L2CAP_ConfResp in conf_resp and
                              conf_resp.scid == scid and
                              conf_resp.result == 0, # success
            lambda loop, conf_resp: conf_resp)
    loop.send(conf_req)
    loop.cont()

    
def handle_information_negotiation_process(l2cap_loop):
    # There is an inherent race that might exist in the information negotiation process.
    # If both sides of the connection are waiting for the other side to send the first info req
    # the connection will be deadlocked. So we start by sending are own info request.
    
    info_req = L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=1) / L2CAP_InfoReq(type=2)
    l2cap_loop.send(info_req)

    l2cap_loop.on(is_info_req_features, reply_to_info_req_features)
    l2cap_loop.on(is_info_rsp_features, lambda loop, pkt: True)

    # We wait for two events to be handled:
    # 1. An info request was received, and we have replied with 'info_rsp'
    #    (reply_to_info_req_features returned True)
    # 2. An info rsp message was returned (in response to the info_req we initially sent).
    # The order of the two events is not important, so we just wait for two 'True' returns.
    
    assert l2cap_loop.cont() == [True]
    assert l2cap_loop.cont() == [True]

    # The same practice as above, only for the "fixed channels" info request\response.
    
    info_req = L2CAP_Hdr(cid=1) / L2CAP_CmdHdr(id=1) / L2CAP_InfoReq(type=3)
    l2cap_loop.send(info_req)
    l2cap_loop.on(is_info_req_fixed_channels, reply_to_info_req_fixed_channels)
    l2cap_loop.on(is_info_rsp_fixed_channels, lambda loop, pkt: True)
    
    assert l2cap_loop.cont() == [True]
    assert l2cap_loop.cont() == [True]
    
    
def create_l2cap_connection(interface, target, psm='SDP', with_mutual_config=True, pcap_path=None):
    os.system("hciconfig %s down" % interface)
    
    if pcap_path:
        user_socket = BluetoothUserSocket_WithTrace(pcap_path, hci_devid(interface))
    else:
        user_socket = BluetoothUserSocket(hci_devid(interface))
        
    loop = Loop(user_socket)
    reset(loop)
    is_connected, handle = acl_connect(loop, target)
    if not is_connected:
        print("Unable to connect target via Bluetooth")
        sys.exit(1)
    
    print('Handle = %04x' % (handle, ))
    
    # Configure connection and initiate config handshake
    ignore_evt(loop, 0x20) # Page scan repetition mode
    ignore_evt(loop, 0x1b) # Max slots change

    read_remote_supported_features(loop, handle)

    l2cap_loop = Loop(L2CAP(loop, handle))

    ########################################
    # This Is the 'naieve' way to handle the information request\response:
    # Wait for the peer to send it's requests, and respond to them,
    # And then send are own info requets.
    ########################################
    # l2cap_loop.on(is_info_req_features, reply_to_info_req_features)
    # l2cap_loop.on(is_info_req_fixed_channels, reply_to_info_req_fixed_channels)

    # send_info_req_features(l2cap_loop)
    # send_info_req_fixed_channels(l2cap_loop)
    
    # The above code tends to deadlock on certain conditions (some race condition).
    # So this following functions works better:
    
    handle_information_negotiation_process(l2cap_loop)
    
    # An ACL Connection is established, create a l2cap connection over it.
    dcid = l2cap_connect(l2cap_loop, psm=psm)
    print('DCID = %x' % (dcid, ))

    if with_mutual_config:
        l2cap_mutual_configration(l2cap_loop, dcid)
    
    return l2cap_loop, dcid

def l2cap_mutual_configration(l2cap_loop, dcid):
    # Register handler to accept any configuration request coming from the other peer.
    reply_to_conf_req_accept(l2cap_loop, OUR_LOCAL_SCID, dcid)
    # Negotiate our own configuration parametres, using the lockstep procedure (using the pending state)
    standard_conf_process(l2cap_loop, OUR_LOCAL_SCID, dcid)
    # Reaching this phase, the connection is in CONNECTED state.
    
def main(src_hci, dst_bdaddr, pcap_path=None):
    l2cap_loop, _ = create_l2cap_connection(src_hci, dst_bdaddr, pcap_path=pcap_path)

    # Seding 'test' to the established l2cap connection
    print("Sending 'test' in l2cap connection")
    l2cap_loop.send(L2CAP_Hdr(cid=OUR_LOCAL_SCID) / Raw('test'))
    l2cap_loop.on(lambda pkt: True,
                  lambda loop, pkt: pkt)
    
    # And printing the returned data.
    print(repr(l2cap_loop.cont()))
    l2cap_loop.finish()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: l2cap_infra.py <src-hci> <dst-bdaddr> (<pcap_path>)")
    else:
        main(*sys.argv[1:])

