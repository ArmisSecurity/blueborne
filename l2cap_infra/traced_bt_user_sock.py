from scapy.layers.bluetooth import *
from pcap_file import PcapFile

class BluetoothUserSocket_WithTrace(BluetoothUserSocket):
    def __init__(self, pcap_path, *args, **kws):
        self._pcap = PcapFile(pcap_path, 'H4')
        super(BluetoothUserSocket_WithTrace, self).__init__(*args, **kws)

    def raw(self, x):
        """Convert a str, a packet to bytes"""
        if x is None:
            return None
        if hasattr(x, "__bytes__"):
            return x.__bytes__()
        try:
            return chr(x)
        except (ValueError, TypeError):
            return str(x)
        
    def send(self, x, *args, **kws):
        # In H4, the 4 first bytes are the direction of the packet/
        self._pcap.write_packet('\x00\x00\x00\x00' + self.raw(x))
        
        return super(BluetoothUserSocket_WithTrace, self).send(x, *args, **kws)

    def recv(self, *args, **kws):
        data = super(BluetoothUserSocket_WithTrace, self).recv(*args, **kws)
        
        # In H4, the 4 first bytes are the direction of the packet/
        self._pcap.write_packet('\x00\x00\x00\x01' + self.raw(data))
        
        return data
