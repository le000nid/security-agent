"""Арсенал RFI: векторы SSRF/RFI против наивных и охраняемых операций."""

from __future__ import annotations

import ipaddress

import pytest

from app.agent.arsenal import rfi
from app.agent.arsenal.core import DefenseHold, NaiveRejected


@pytest.fixture()
def sandbox():
    with rfi.build_context() as ctx:
        yield ctx


@pytest.mark.parametrize("vector", rfi.VECTORS, ids=lambda v: v.id)
def test_vector_unguarded_and_guarded(sandbox, vector):
    attack_ok, attack_detail = rfi.naive_run(sandbox, vector.id)
    assert attack_ok, f"наивная реализация устояла: {attack_detail}"
    hold_ok, hold_layer, hold_detail = rfi.guarded_run(sandbox, vector.id)
    assert hold_ok, f"охраняемая реализация пропустила: {hold_detail}"
    assert hold_layer in vector.stopped_by


def test_naive_blacklist_blocks_only_plain_forms():
    with pytest.raises(NaiveRejected):
        rfi.naive_sync("http://127.0.0.1/admin")
    # длинная форма IPv6 и десятичный литерал фильтр не видит
    detail = rfi.naive_sync("http://2130706433/admin")
    assert "127.0.0.1" in detail


def test_host_literal_canonicalization():
    assert rfi._host_literal("2130706433") == ipaddress.ip_address("127.0.0.1")
    assert rfi._host_literal("0x7f000001") == ipaddress.ip_address("127.0.0.1")
    assert rfi._host_literal("0177.0.0.1") == ipaddress.ip_address("127.0.0.1")
    assert rfi._host_literal("0:0:0:0:0:0:0:1") == ipaddress.ip_address("::1")
    assert rfi._host_literal("fd00:ec2::254") == ipaddress.ip_address("fd00:ec2::254")
    assert rfi._host_literal("trusted.example") is None


def test_safe_remote_url_layers():
    with pytest.raises(DefenseHold) as userinfo:
        rfi.safe_remote_url(
            "https://trusted.example@attacker.example/x",
            allowlist=rfi.AVATAR_ALLOWLIST,
        )
    assert userinfo.value.layer == "R5"

    with pytest.raises(DefenseHold) as tab:
        rfi.safe_remote_url(
            "https://trusted.example%09@attacker.example/x",
            allowlist=rfi.AVATAR_ALLOWLIST,
        )
    assert tab.value.layer == "R2"

    with pytest.raises(DefenseHold) as crlf:
        rfi.safe_remote_url(
            "https://trusted.example/x?next=%0d%0aX-Injected:%20yes",
            allowlist=rfi.AVATAR_ALLOWLIST,
        )
    assert crlf.value.layer == "R2"

    with pytest.raises(DefenseHold) as data_url:
        rfi.safe_remote_url(
            "data://text/plain;base64,QVJTRU5BTC1QQVlMT0FE",
            allowlist=rfi.AVATAR_ALLOWLIST,
        )
    assert data_url.value.layer == "R1"

    with pytest.raises(DefenseHold) as decimal:
        rfi.safe_remote_url("http://2130706433/admin", allowlist=rfi.SYNC_ALLOWLIST)
    assert decimal.value.layer == "R3"

    with pytest.raises(DefenseHold) as v6:
        rfi.safe_remote_url(
            "http://[0:0:0:0:0:0:0:1]/admin", allowlist=rfi.SYNC_ALLOWLIST
        )
    assert v6.value.layer == "R3"

    # доверенный хост проходит проверку целиком
    checked = rfi.safe_remote_url(
        "https://trusted.example/page", allowlist=rfi.AVATAR_ALLOWLIST
    )
    assert checked.startswith("https://trusted.example")


def test_redirect_pin_stops_cross_origin_hop():
    with pytest.raises(DefenseHold) as pin:
        rfi.pinned_fetch(
            "https://trusted.example/redirect?to=http://attacker.example/exfil",
            allowlist=rfi.AVATAR_ALLOWLIST,
        )
    assert pin.value.layer in {"R6", "R5"}
