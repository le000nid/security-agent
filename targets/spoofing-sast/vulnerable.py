"""Never execute: inert syntax fixtures for static analysis only."""

from scapy.all import ARP, DNSRR


def forged_arp_reply(victim, gateway):
    return ARP(op=2, pdst=victim, psrc=gateway)


def forged_dns_answer(name, replacement):
    return DNSRR(rrname=name, rdata=replacement)
