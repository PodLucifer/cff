import socket
from dnslib import DNSRecord, QTYPE

def start_dns_server():
    # Nastavení DNS serveru (používáme localhost a port 53 pro testování)
    server_ip = '10.0.1.12'
    server_port = 53

    # Vytvoření socketu pro příjem DNS požadavků
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"[+] DNS server běží na {server_ip}:{server_port}")

    while True:
        # Čekání na příchozí DNS požadavek
        data, addr = sock.recvfrom(512)  # Maximální velikost DNS požadavku
        print(f"[+] Přijato požadavky od {addr}")

        # Zpracování požadavku
        try:
            # Dekódujeme DNS požadavek
            dns_request = DNSRecord.parse(data)

            # Vytvoření DNS odpovědi
            dns_response = dns_request.reply()
            dns_response.add_answer(*dns_request.qr)

            # Přidání vlastní odpovědi
            for q in dns_request.questions:
                dns_response.add_answer(*q, rdata="HELLO!".encode('utf-8'))

            # Odeslání odpovědi zpět klientovi
            sock.sendto(dns_response.pack(), addr)
            print(f"[+] Odeslána odpověď 'HELLO!' na {addr}")

        except Exception as e:
            print(f"[-] Chyba při zpracování požadavku: {e}")

if __name__ == '__main__':
    start_dns_server()
