BlueBorne Exploits & Framework
=============================

This repository contains a PoC code of various exploits for the BlueBorne vulnerabilities.

Under 'android' exploits for the Android RCE vulnerability (CVE-2017-0781), and the SDP Information leak vulnerability (CVE-2017-0785) can be found.

Under 'linux-bluez' exploits for the Linux-RCE vulnerability (CVE-2017-1000251) can be found (for Amazon Echo, and Samsung Gear S3).

Under 'l2cap_infra' a general testing framework to send and receive raw l2cap messages (using scapy) can be found.

Under 'nRF24_BDADDR_Sniffer' a tool to capture bluetooth mac addresses (BDADDR) over the air, using a nRF24L01 chip

For more details on BlueBorne, you may read the full technical white paper available here:

https://www.armis.com/blueborne/

In addition a several detailed blog posts on the exploitation of these vulnerability can be found here:

https://www.armis.com/blog/


===============

Dependencies:

    pip2 packages: pybluez, pwn, scapy
    
    - sudo apt-get install libbluetooth-dev
    - sudo pip2 install pybluez pwn scapy

    To run the exploits, the root of this repository needs to be in the PYTHONPATH:
    
    export PYTHONPATH=$PYTHONPATH:<repo-path>
