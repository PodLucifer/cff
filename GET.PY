#!/usr/bin/env python
# __author__ = 'c4mx'
from pbkdf2 import PBKDF2
from binascii import a2b_hex
import hmac, hashlib, binascii


# passphrase: WPA wifi password
def calc_pmk(passphrase, ssid):
    return PBKDF2(passphrase, ssid, 4096).read(32)

# pmk: pairwise master key
def calc_ptk(pmk, salt, size=64):
    pke = 'Pairwise key expansion'.encode()
    i = 0
    r = b''

    while len(r) < size:
        msg = pke + b'\x00' + salt + bytes([i])
        hmacsha1 = hmac.new(pmk, msg, hashlib.sha1)
        i += 1
        r += hmacsha1.digest()

    return r[:size]

# kck: Key Confirmation Key = ptk[:16]
def calc_mic(kck, data):
    return hmac.new(kck, data, hashlib.sha1).digest()[:16]

def zero_mic_frame(frame_hex, mic_hex):
    return a2b_hex(frame_hex.replace(mic_hex, '0'*len(mic_hex)))

# SSID and passphrase here are edited
ssid = '...SSID...'
passphrase = '...Passphrase...'
mac_ap = a2b_hex('4cd542e45df2')
mac_cl = a2b_hex('257f30afbe0f')
anonce = a2b_hex('b22e6d0128ac8336813ead06ba1e4fc0e7be4b83af5417bd8f8568a148158b42')
snonce = a2b_hex('4eb8dd754c777fa6971e6a3c43ef05620a28ff6dd7925e2a7d5b9468c7394a65')
ptk_salt = min(mac_ap, mac_cl) + max(mac_ap, mac_cl) + min(anonce, snonce) + max(anonce, snonce)

# the 2nd Eapol frame (message n.2)
frame2_hex = '0103007502010a000000000000000000014eb8dd754c777fa6971e6a3c43ef05620a28ff6dd7925e2a7d5b9468c7394a650000000000000000000000000000000000000000000000000000000000000000bf84b4ded270366de31b5f8c5a9164e5001630140100000fac020100000fac040100000fac028000'
mic2_hex = 'bf84b4ded270366de31b5f8c5a9164e5'
frame2_with_zero_mic = zero_mic_frame(frame2_hex, mic2_hex)

pmk = calc_pmk(passphrase, ssid)
print(f'pmk = {pmk.hex()}')

ptk = calc_ptk(pmk, ptk_salt)
print(f'ptk = {ptk.hex()}')

kck = ptk[:16]
my_mic2 = calc_mic(kck, frame2_with_zero_mic)
print(f'my_mic2= {my_mic2.hex()}\nmic2 = {mic2_hex}')
