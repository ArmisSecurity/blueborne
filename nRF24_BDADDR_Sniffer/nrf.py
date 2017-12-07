import os
import sys
import time
import random

from ctypes import cdll, c_int, c_char_p, c_uint32, c_int, c_void_p, byref, c_uint8

import bitarray
import spidev


BTBB = cdll.LoadLibrary("/usr/local/lib/libbtbb.so")

BTBB.btbb_init.argtypes = [c_int]
BTBB.btbb_find_ac.argtypes = [c_char_p, c_int, c_uint32, c_int, c_void_p]
BTBB.btbb_packet_get_lap.argtypes = [c_void_p]
BTBB.try_clock.argtypes = [c_int, c_void_p]
BTBB.btbb_packet_set_data.argtypes = [c_void_p, c_char_p, c_int, c_uint8, c_uint32]


FLUSH_RX = 0xe2
R_RX_PAYLOAD = 0x61
R_REGISTER = 0x00
W_REGISTER = 0x20
REGISTER_MASK = 0x1f

EN_AA = 0x01
EN_RXADDR = 0x02
SETUP_AW = 0x03
RF_CH = 0x05
RF_SETUP = 0x06
FEATURE = 0x1d
CONFIG = 0x00
STATUS = 0x07
RX_PW_P0 = 0x11
RX_ADDR_P0 = 0xa

RX_FIFO_EMPTY = 0b1110
PRIM_RX = 1 << 0
PWR_UP  = 1 << 1
RX_DR = 1 << 6
ERX_P0 = 1 << 0

PAYLOAD_SIZE = 16
BR_1MBPS_SETUP = 0
BR_CONFIG = 0
PROMISC_MAC = b'\x55\x55'
RX_PIPE_MAC_LEN = 5


class NRF24SpiError(Exception):
    pass


class NRF24BREDR(object):
    def __init__(self, spi):
        self.spi = spi
        BTBB.btbb_init(4)
        self._btbb_packet = c_void_p(BTBB.btbb_packet_new())

    def write_reg_byte(self, reg, value):
        self.spi.xfer2([W_REGISTER | (REGISTER_MASK & reg), value])
    
    def write_reg_multi_bytes(self, reg, data, pad_len):
        write = list(data.ljust(pad_len, b'\x00'))
        self.spi.xfer2([W_REGISTER | (REGISTER_MASK & reg)] + write)

    def read_reg(self, reg, size=1):
        resp = self.spi.xfer2([R_REGISTER | (REGISTER_MASK & RF_CH)] + [0xff] * size)
        return resp[1:]

    def flush_rx(self):
        self.spi.xfer2([FLUSH_RX])

    def get_status(self):
        return self.spi.xfer2([0xff])[0]

    def clear_status(self, status=None):
        status = self.read_reg(STATUS)[0]
        self.write_reg_byte(STATUS, status | RX_DR)

    def set_channel(self, chan):
        self.write_reg_byte(RF_CH, chan)

    def setup(self, chan):
        self._spi_test()
        # Set GFSK data rate via RF_SETUP
        self.write_reg_byte(RF_SETUP, BR_1MBPS_SETUP)
        # Disable auto ack
        self.write_reg_byte(EN_AA, 0)
        # Disable dynamic payloads
        self.write_reg_byte(FEATURE, 0)
        # Set MAC len
        self.write_reg_byte(SETUP_AW, len(PROMISC_MAC) - 2)
        # Setup pipe 0 for PROMISC_MAC RX and payload size
        self.write_reg_multi_bytes(RX_ADDR_P0, PROMISC_MAC[::-1], RX_PIPE_MAC_LEN)
        self.write_reg_byte(RX_PW_P0, PAYLOAD_SIZE)
        self.write_reg_byte(EN_RXADDR, ERX_P0)
        # Set config (disable CRC & power up)
        self.write_reg_byte(CONFIG, BR_CONFIG | PWR_UP | PRIM_RX)
        # Prepare for RX of first packet
        self.clear_status()
        self.flush_rx()
        # Set channel
        self.set_channel(chan)

    def _spi_test(self):
        for _ in range(5):
            chan = random.randint(0, 80)
            self.write_reg_byte(RF_CH, chan)
            if self.read_reg(RF_CH) != [chan]:
                raise NRF24SpiError('SPI connection to NRF not working')
        self.write_reg_byte(RF_CH, 0)

    def poll(self):
        status = self.get_status()
        if status & RX_DR != RX_DR and status & RX_FIFO_EMPTY == RX_FIFO_EMPTY:
            return
        resp = self.spi.xfer2([R_RX_PAYLOAD] + [0xff] * (PAYLOAD_SIZE + 1))
        self.clear_status()
        return bytes(resp[1:])

    def parse_bredr(self, packet, pre=PROMISC_MAC, max_depth=(PAYLOAD_SIZE*8)-64):
        bits = bitarray.bitarray()
        bits.frombytes(pre + packet)
        bits_data = bytes(bits.tolist())

        offset = BTBB.btbb_find_ac(bits_data,
                                   max_depth,
                                   0xffffffff,
                                   0,
                                   byref(self._btbb_packet))
        if offset < 0:
            return
        bits_data = bits_data[offset:]

        lap = BTBB.btbb_packet_get_lap(self._btbb_packet)
        BTBB.btbb_packet_set_data(self._btbb_packet, bits_data, len(bits_data), 0, 0)

        # Bruteforce CLK1-6 values (5 bits)
        uap_candidates = set([BTBB.try_clock(i, self._btbb_packet)
                              for i in range(64)])
        return (lap, uap_candidates)


def main(spi_id, spi_cs, chan=None):
    spi = spidev.SpiDev()
    spi.open(int(spi_id), int(spi_cs))
    spi.max_speed_hz = 2000000

    nrf = NRF24BREDR(spi)
    nrf.setup(int(chan) if chan else 0)

    cur_chan = 0
    last_time = time.time()

    while True:
        pack = nrf.poll()

        if chan is None and time.time() - last_time > 0.5:
            nrf.set_channel(2 + cur_chan)
            print('Hopped to chan: %d' % (cur_chan,))
            cur_chan = (cur_chan + 1) % 79
            last_time = time.time()

        if not pack:
            continue
        parsed = nrf.parse_bredr(pack)
        if not parsed:
            continue

        lap, uap_candidates = parsed
        print('LAP: %06x, UAPs: %s' % (lap, ','.join(['%02x' % (x,) for x in uap_candidates])))
	

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: nrf.py <spi-id> <spi-cs> [<chan>]")
        print("spi-id - The id of the spi interface used")
        print("spi-cs - The chip select where the NRF24 is connected")
        print("chan   - Optional param, to set the NRF24 to a specific channel (without it, the NRF24 will hop channles")
    else:
        main(*sys.argv[1:])
