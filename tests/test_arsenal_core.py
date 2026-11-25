"""Контракты ядра арсенала: реестры, матрицы, кампании и CLI-диспетчер."""

from __future__ import annotations

import pytest

from app.agent import arsenal
from app.cli import run as run_cli

EXPECTED_VECTORS = {"lfi": 31, "rfi": 26, "sqli": 21}
EXPECTED_LAYERS = {"lfi": 11, "rfi": 8, "sqli": 7}


@pytest.mark.parametrize("category", sorted(EXPECTED_VECTORS))
def test_registry_counts_and_unique_ids(category):
    module = arsenal.CATEGORIES[category]
    assert len(module.VECTORS) == EXPECTED_VECTORS[category]
    assert len({v.id for v in module.VECTORS}) == len(module.VECTORS)
    assert len(module.LAYERS) == EXPECTED_LAYERS[category]
    assert len({layer.id for layer in module.LAYERS}) == len(module.LAYERS)


@pytest.mark.parametrize("category", sorted(EXPECTED_VECTORS))
def test_stopped_by_references_known_layers(category):
    module = arsenal.CATEGORIES[category]
    layer_ids = {layer.id for layer in module.LAYERS}
    for vector in module.VECTORS:
        assert vector.stopped_by, vector.id
        assert set(vector.stopped_by) <= layer_ids, vector.id


@pytest.mark.parametrize("category", sorted(EXPECTED_VECTORS))
def test_campaign_defense_stays_ahead(category):
    result = arsenal.run_campaign(category)
    assert len(result.outcomes) == EXPECTED_VECTORS[category]
    assert result.ok, result.render()


@pytest.mark.parametrize("category", sorted(EXPECTED_VECTORS))
def test_matrix_renders_with_all_layers(category):
    text = arsenal.render_matrix(category)
    for layer in arsenal.CATEGORIES[category].LAYERS:
        assert layer.id in text
    for vector in arsenal.CATEGORIES[category].VECTORS:
        assert vector.id in text


def test_vector_ids_unique_across_domains():
    ids = [v.id for m in arsenal.CATEGORIES.values() for v in m.VECTORS]
    assert len(ids) == len(set(ids))


def test_docs_cheatsheet_lists_every_domain():
    text = arsenal.render_docs()
    for title in arsenal.CATEGORY_TITLES.values():
        assert title in text
    assert "python -m app.main arsenal" in text


def test_cli_arsenal_docs_and_campaign_exit_codes(capsys):
    assert run_cli(["arsenal", "--mode", "docs"]) == 0
    assert "Арсенал v10" in capsys.readouterr().out
    assert run_cli(["arsenal", "--category", "all", "--mode", "campaign"]) == 0
    out = capsys.readouterr().out
    assert "ЗАЩИТА ВПЕРЕДИ АТАКИ" in out


def test_cli_arsenal_matrix_and_unknown_category(capsys):
    assert run_cli(["arsenal", "--category", "sqli", "--mode", "matrix"]) == 0
    assert "Матрица" in capsys.readouterr().out
    with pytest.raises(SystemExit) as excinfo:
        run_cli(["arsenal", "--category", "nope"])
    assert excinfo.value.code == 2
