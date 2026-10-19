"""Benign packet inspection/configuration examples; no forged replies."""


def observe_arp(record):
    return {"source": record.get("source"), "destination": record.get("destination")}


def configured_dns(name, records):
    return records.get(name)
