BlueBorne L2CAP Testing Framework
=================================

This direcotory contains a general testing framework to send and receive raw l2cap messages (using scapy).
It is used to establish L2CAP connections, and allows the ability to control all l2cap messages sent in the process of creating the connection.

To run a simple l2cap connection test:
    sudo python2 l2cap_infra.py <src-hci> <target-bdaddr> (optional-pcap-path)
    