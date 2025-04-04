import sys
from scapy.all import *
from hashlib import pbkdf2_hmac
from binascii import a2b_hex, b2a_hex, Error as BinasciiError
from struct import pack
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
            # Check if it's a Key (Message 2 of 4)
            if eapol_layer.type == 3 and eapol_layer.key_mic and not mic:
                mic = eapol_layer.key_mic
                print(f"Extracted MIC: {mic.hex()}")
                if not snonce:
                    snonce = eapol_layer.key_nonce
                    print(f"Extracted SNonce: {snonce.hex()}")

            # Check if it's a Key (Message 3 of 4) to extract ANonce
            if eapol_layer.type == 3 and eapol_layer.key_ack and not anonce:
                anonce = eapol_layer.key_nonce
                print(f"Extracted ANonce: {anonce.hex()}")

            # Extract STA MAC and BSSID
            if not sta_mac or not bssid:
                sta_mac = packet.addr2
                bssid = packet.addr1
                print(f"Extracted STA MAC: {sta_mac}")
                print(f"Extracted BSSID: {bssid}")

            # Break the loop if all values are found
            if mic and snonce and sta_mac and bssid and anonce:
                break

        # Extract SSID from Beacon packets
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
    
    return snonce, anonce, sta_mac, bssid, ssid

def derive_psk(passphrase, ssid):
    ssid_bytes = ssid.encode()
    pmk = pbkdf2_hmac('sha1', passphrase.encode(), ssid_bytes, 4096, 32)
    print(f"Derived PMK: {pmk.hex()}")
    return pmk

def derive_ptk(pmk, snonce, anonce, sta_mac, bssid):
    try:
        bssid_bytes = a2b_hex(bssid.replace(':', ''))
        sta_mac_bytes = a2b_hex(sta_mac.replace(':', ''))
        snonce_bytes = a2b_hex(snonce)
        anonce_bytes = a2b_hex(anonce)
    except BinasciiError as e:
        print(f"Error converting to bytes: {e}")
        return None
    
    a = "Pairwise key expansion"
    b = min(bssid_bytes, sta_mac_bytes) + max(bssid_bytes, sta_mac_bytes) + min(anonce_bytes, snonce_bytes) + max(anonce_bytes, snonce_bytes)
    
    ptk = hmac.new(pmk, a.encode() + b, digestmod='sha1').digest()
    print(f"Derived PTK: {ptk.hex()}")
    return ptk

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python extract.py <input_file.cap/pcap> <passphrase>")
        sys.exit(1)

    input_file = sys.argv[1]
    passphrase = sys.argv[2]
    
    snonce, anonce, sta_mac, bssid, ssid = extract_mic_and_nonce_and_ssid(input_file)
    
    if snonce and anonce and sta_mac and bssid and ssid:
        pmk = derive_psk(passphrase, ssid)
        ptk = derive_ptk(pmk, snonce, anonce, sta_mac, bssid)
    else:
        print("Failed to extract necessary handshake information.")
