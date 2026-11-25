"""Арсенал LFI: каждый вектор поддается наивной реализации и остановлен слоями."""

from __future__ import annotations

import pytest

from app.agent.arsenal import lfi
from app.agent.arsenal.core import DefenseHold, NaiveRejected


@pytest.fixture()
def sandbox():
    with lfi.build_context() as ctx:
        yield ctx


@pytest.mark.parametrize("vector", lfi.VECTORS, ids=lambda v: v.id)
def test_vector_unguarded_and_guarded(sandbox, vector):
    if vector.id in sandbox.unavailable():
        pytest.skip("symlink не поддерживается платформой")
    attack_ok, attack_detail = lfi.naive_run(sandbox, vector.id)
    assert attack_ok, f"наивная реализация устояла: {attack_detail}"
    hold_ok, hold_layer, hold_detail = lfi.guarded_run(sandbox, vector.id)
    assert hold_ok, f"охраняемая реализация пропустила: {hold_detail}"
    assert hold_layer in vector.stopped_by


def test_naive_rejects_plain_traversal():
    with pytest.raises(NaiveRejected):
        lfi.naive_resolve("../outside/secret.txt")


def test_naive_pipeline_decodes_twice():
    # двойное декодирование: sanitizer видит %252e, хранилище — ../
    assert lfi.naive_resolve("..%252foutside%2fsecret.txt").startswith("../")


def test_safe_file_param_layers(sandbox):

    with pytest.raises(DefenseHold) as decode_first:
        lfi.safe_file_param(sandbox, "%2e%2e%2foutside%2fsecret.txt")
    assert decode_first.value.layer == "G2"  # после G1-декодирования виден ../

    with pytest.raises(DefenseHold) as dotfile:
        lfi.safe_file_param(sandbox, ".env")
    assert dotfile.value.layer == "G4"

    with pytest.raises(DefenseHold) as backup:
        lfi.safe_file_param(sandbox, "config.py.bak")
    assert backup.value.layer == "G4"

    with pytest.raises(DefenseHold) as wrapper:
        lfi.safe_file_param(sandbox, "file:///etc/hostname")
    assert wrapper.value.layer == "G3"

    with pytest.raises(DefenseHold) as member:
        lfi.safe_file_param(sandbox, "docs.zip#../escape.txt")
    assert member.value.layer == "G3"

    with pytest.raises(DefenseHold) as env_var:
        lfi.safe_file_param(sandbox, "$HOME/secret.txt")
    assert env_var.value.layer == "G5"

    with pytest.raises(DefenseHold) as parent:
        lfi.safe_file_param(sandbox, "../outside/secret.txt")
    assert parent.value.layer == "G2"

    # легитимный путь проходит все слои
    assert lfi.safe_file_param(sandbox, "notes.md").name == "notes.md"


def test_containment_holds_for_symlink_hop(sandbox):
    if not sandbox.symlinks_supported:
        pytest.skip("symlink не поддерживается платформой")
    from app.http_guard import GuardError

    with pytest.raises(GuardError):
        lfi.contained_path(sandbox.base, "out_link.txt")
