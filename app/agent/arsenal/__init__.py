"""Арсенал v8: пары «вектор атаки — слой защиты» для SAST-доменов.

Домены: ``lfi`` (14 векторов / 7 слоёв), ``rfi`` (15/7), ``sqli`` (14/6).
Каждый вектор обязан срабатывать на наивной песочнице и останавливаться
охраняемой реализацией; кампании прогоняются через CLI
(``python -m app.main arsenal``), benchmark-модули и pytest.
"""

from __future__ import annotations

from app.agent.arsenal import core, lfi, rfi, sqli
from app.agent.arsenal.core import CampaignResult, Layer, Vector, VectorOutcome

CATEGORIES = {"lfi": lfi, "rfi": rfi, "sqli": sqli}

CATEGORY_TITLES = {
    "lfi": "LFI: локальное включение файлов",
    "rfi": "RFI/SSRF: удалённое включение",
    "sqli": "SQLI: инъекции в SQLite",
}


def run_campaign(category: str) -> CampaignResult:
    """Прогнать кампанию одной категории (векторы через обе реализации)."""
    if category not in CATEGORIES:
        raise KeyError(f"unknown arsenal category: {category}")
    return CATEGORIES[category].campaign()


def run_all_campaigns() -> list[CampaignResult]:
    return [run_campaign(category) for category in CATEGORIES]


def render_matrix(category: str) -> str:
    module = CATEGORIES[category]
    return core.render_matrix(CATEGORY_TITLES[category], module.VECTORS, module.LAYERS)


def render_docs() -> str:
    """Краткая шпаргалка арсенала для терминала."""
    lines = ["Арсенал v8 — атака и защита в SAST-доменах (LFI/RFI/SQLI)", ""]
    for category, module in CATEGORIES.items():
        lines.append(f"[{CATEGORY_TITLES[category]}]")
        lines.append(
            f"  векторов: {len(module.VECTORS)}, слоёв защиты: {len(module.LAYERS)}"
        )
        lines.append(
            "  слои: "
            + ", ".join(f"{layer.id} ({layer.name})" for layer in module.LAYERS)
        )
        lines.append("")
    lines.append("Запуск: python -m app.main arsenal --category all --mode campaign")
    lines.append("Матрица: python -m app.main arsenal --category sqli --mode matrix")
    return "\n".join(lines)


__all__ = [
    "CATEGORIES",
    "CATEGORY_TITLES",
    "CampaignResult",
    "Layer",
    "Vector",
    "VectorOutcome",
    "core",
    "render_docs",
    "render_matrix",
    "run_all_campaigns",
    "run_campaign",
]
