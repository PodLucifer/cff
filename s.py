from pbkdf2 import PBKDF2
import hmac, hashlib
from scapy.all import rdpcap
from binascii import a2b_hex
from scapy.layers.eap import EAPOL


def get_msg(pcap_file):
    flags = []
    packets = rdpcap(pcap_file)
    anonce, snonce, ap_mac, client_mac, eapol_payload, mic = None, None, None, None, None, None
    for packet in packets:
        if packet.haslayer(EAPOL):
            eapol_packet = packet[EAPOL]
            if not anonce:
                anonce = eapol_packet.key_nonce
            elif not snonce and bytes(eapol_packet) not in flags:
                snonce = eapol_packet.key_nonce
                if packet.addr2 and not ap_mac:
                    ap_mac = a2b_hex(packet.addr2.replace(":", ""))
                if packet.addr1 and not client_mac:
                    client_mac = a2b_hex(packet.addr1.replace(":", ""))
            elif not mic and bytes(eapol_packet) not in flags:
                mic = eapol_packet.key_mic
                eapol_payload = bytes(eapol_packet)
                break
        flags.append(bytes(packet[EAPOL]))
    if not all([anonce, snonce, ap_mac, client_mac, eapol_payload, mic]):
        print("无法提取完整握手数据。")
        return False
    return anonce, snonce, ap_mac, client_mac, eapol_payload, mic
    # print(anonce, snonce, ap_mac, client_mac, eapol_payload, mic)


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
    return a2b_hex(frame_hex.replace(mic_hex, '0' * len(mic_hex)))


def calc(pcap_file, ssid, passphrase):
    pcap_file = pcap_file
    anonce, snonce, ap_mac, client_mac, eapol_payload, mic = get_msg(pcap_file)
    ptk_salt = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    frame2_hex = eapol_payload.hex()
    mic2_hex = mic.hex()
    frame2_with_zero_mic = zero_mic_frame(frame2_hex, mic2_hex)

    pmk = calc_pmk(passphrase, ssid)
    # print(f'pmk = {pmk.hex()}')
    ptk = calc_ptk(pmk, ptk_salt)
    # print(f'ptk = {ptk.hex()}')
    kck = ptk[:16]
    calc_mic2 = calc_mic(kck, frame2_with_zero_mic)
    # print(f'calc_mic2= {calc_mic2.hex()}\nmic2 = {mic2_hex}')
    if calc_mic2.hex() == mic2_hex:
        return True,passphrase
    return None,passphrase

