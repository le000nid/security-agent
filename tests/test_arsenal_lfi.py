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


# --------------------------------------------------------------------------
# v10: комплексные цепочки и простой залп — явные проверки новых слоёв
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vector_id", sorted(lfi._SYMLINK_VECTORS))
def test_naive_symlink_vectors_succeed(sandbox, vector_id):
    if not sandbox.symlinks_supported:
        pytest.skip("symlink не поддерживается платформой")
    attack_ok, detail = lfi.naive_run(sandbox, vector_id)
    assert attack_ok, f"наивная реализация устояла: {detail}"


def test_toctou_guarded_layer_is_g8(sandbox):
    if not sandbox.symlinks_supported:
        pytest.skip("symlink не поддерживается платформой")
    hold_ok, layer, code = lfi.guarded_run(sandbox, "lfi_toctou_swap")
    assert hold_ok
    assert layer == "G8"
    assert code == "path_swapped_between_check_and_open"


def test_safe_open_consistent_holds_on_swap(sandbox):
    if not sandbox.symlinks_supported:
        pytest.skip("symlink не поддерживается платформой")
    with pytest.raises(DefenseHold) as hold:
        lfi.safe_open_consistent(sandbox, "report.txt")
    assert hold.value.layer == "G8"


def test_safe_extract_tar_rejects_parent_and_symlink_members(sandbox):
    with pytest.raises(DefenseHold) as slip:
        lfi.safe_extract_tar(sandbox, "evil-extract.tar")
    assert slip.value.layer == "G9"
    assert slip.value.code == "parent_segment_in_member"
    if not sandbox.symlinks_supported:
        pytest.skip("symlink не поддерживается платформой")
    with pytest.raises(DefenseHold) as chain:
        lfi.safe_extract_tar(sandbox, "chain.tar")
    assert chain.value.layer == "G9"
    assert chain.value.code == "non_regular_member"


def test_safe_archive_member_limits_and_depth(sandbox):
    with pytest.raises(DefenseHold) as bomb:
        lfi.safe_archive_member(sandbox, "bomb.zip")
    assert bomb.value.layer == "G10"
    assert bomb.value.code == "member_size_exceeded"
    with pytest.raises(DefenseHold) as nested:
        lfi.safe_archive_member(sandbox, "nested.zip")
    assert nested.value.layer == "G11"
    assert nested.value.code == "nested_archive_forbidden"


@pytest.mark.parametrize(
    ("payload", "layer"),
    [
        ("..%2foutside%2fsecret.txt", "G2"),
        ("%2e%2e\\outside\\secret.txt", "G2"),
        ("．．/outside/secret.txt", "G2"),
        ("..%00%2foutside%2fsecret.txt", "G2"),
        ("./..%2foutside%2fsecret.txt", "G2"),
        ("..;/outside/secret.txt", "G2"),
        ("FILE:///etc/hostname", "G3"),
        ("config.py~", "G4"),
        ("config.py.old", "G4"),
        (".config.py.swp", "G4"),
        (".env.local", "G4"),
    ],
)
def test_simple_barrage_layers(sandbox, payload, layer):
    with pytest.raises(DefenseHold) as hold:
        lfi.safe_file_param(sandbox, payload)
    assert hold.value.layer == layer
