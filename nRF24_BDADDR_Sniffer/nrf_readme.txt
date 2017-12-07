This tool uses NRF24 modules/ICs to promiscuously sniff Bluetooth Classic BDADDRs (MACs) of the air

LICENSE: GPLv2

It will talk to an NRF24 module connected to a Linux machine via a spidev (/dev/spi*).
Tested on a Raspberry Pi 3.

On an RPi, connect pins:

    NRF         |     RPi 
  --------------|-----------------
    GND         |     6 (GND)
    VCC         |     1 (3v3)
    CE          |     -
    CSN         |     24 (BCM 8)
    SCLK        |     23 (BCM 11)
    MOSI        |     19 (BCM 10)
    MISO        |     21 (BCM 9)
    IRQ         |     -

Prerequisites:
    libbtbb:
        Compile and install:
        https://github.com/greatscottgadgets/libbtbb

    spidev:
        https://github.com/doceme/py-spidev
        Or just:
        pip install spidev

To use the script with the above pin configurtion on a Raspberry Pi, run the script as follow:

python nrf.py 0 0

---------

