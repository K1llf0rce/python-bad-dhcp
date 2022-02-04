from scapy.all import *
import socket
import helper

def getNewLease(macAddr, interface, timeoutInSeconds: int):
      localiface = interface
      requestMAC = macAddr
      myhostname='vektor'
      localmac = get_if_hwaddr(localiface)
      localmacraw = requestMAC.replace(':','')

      pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=macAddr, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
            UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=macAddr) / DHCP(options=[('message-type', 'discover'), 'end'])
      sendp(pkt, iface=localiface, verbose=0)
      try:
            offer = sniff(iface=localiface, filter="port 68 and port 67",
                        stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 2,
                        timeout=timeoutInSeconds)
      except:
            print("No Offer within timeout limit")
            pass
      server_mac = offer[0]["Ether"].src
      bootp_reply = offer[0]["BOOTP"]
      server_ip = bootp_reply.siaddr
      request_ip = bootp_reply.yiaddr

      pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=macAddr, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / \
            UDP(dport=67, sport=68) / BOOTP(op=1, chaddr=macAddr) / \
            DHCP(options=[('message-type', 'request'), ("client_id", macAddr), ("requested_addr", request_ip),
                              ("server_id", server_ip), 'end'])
      sendp(pkt, iface=localiface, verbose=0)
