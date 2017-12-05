import struct

LINK_TYPES = {
    'BLE': 251,
    'ZIGBEE': 195,
    'H4': 201,
}


class PcapFile(object):
    def __init__(self, filename, link_type="H4"):
        self.filename = filename
        self.link_type = LINK_TYPES[link_type]
        self._file = open(self.filename, "wb")
        self._file.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 0xFFFF, self.link_type))

    def write_packet(self, packet, ts_seconds=0, ts_useconds=0):
        # TODO: timestamp from time..
        self._file.write(struct.pack("<IIII", ts_seconds, ts_useconds, len(packet), len(packet)))
        self._file.write(packet)

    def close(self):
        self._file.close()
