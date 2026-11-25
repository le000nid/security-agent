"""Ядро арсенала v8: реестр векторов, слоёв защиты и оркестрация кампаний.

Арсенал — это тройная бухгалтерия для SAST-доменов (LFI, RFI, SQLI):

* каждый **вектор** атаки обязан сработать на наивной реализации песочницы
  (иначе это не атака, а теория) и обязан быть остановлен защитными слоями
  на охраняемой реализации;
* каждый **слой** защиты — конкретный код, а не список пожеланий; он либо
  ловит вектор, либо тест краснеет;
* **кампания** прогоняет все векторы через обе реализации и печатает таблицу
  вердиктов: атака без защиты должна удаваться, с защитой — нет. Любое
  нарушение пары «наивная поддалась / охраняемая устояла» — дефект дизайна.

Ни один вектор не выходит за пределы локального процесса: RFI-сценарий
использует симулятор DNS и ответов, SQLi — настоящую SQLite в каталоге
песочницы, LFI — реальные файлы во временном каталоге.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Типы реестра
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Layer:
    """Защитный слой: конкретный механизм охраняемой реализации."""

    id: str
    name: str
    description: str


@dataclass(frozen=True)
class Vector:
    """Вектор атаки:payload техники, привязанный к CWE и остановившим слоям."""

    id: str
    name: str
    cwe: str
    technique: str
    stopped_by: tuple[str, ...]


@dataclass
class VectorOutcome:
    """Вердикт кампании по одному вектору."""

    vector: Vector
    naive_ok: bool | None
    naive_detail: str
    guarded_ok: bool | None
    guarded_layer: str
    guarded_detail: str

    @property
    def skipped(self) -> bool:
        return self.naive_ok is None

    @property
    def passed(self) -> bool:
        if self.skipped:
            return True
        return bool(self.naive_ok and self.guarded_ok)

    def row(self) -> str:
        if self.skipped:
            status = "СК   — платформа не поддерживает технику (пропуск)"
            return f"{self.vector.id:34s} {status}"
        attack = "удалась " if self.naive_ok else "ПРОВАЛ "
        hold = "остановлена" if self.guarded_ok else "ПРОРЫВ  "
        return (
            f"{self.vector.id:34s} наивная: {attack} ({self.naive_detail}) | "
            f"охраняемая: {hold} [{self.guarded_layer}] ({self.guarded_detail})"
        )


class DefenseHold(Exception):
    """Защитный слой арсенала остановил вектор (ожидаемое исключение)."""

    def __init__(self, layer: str, code: str, detail: str = ""):
        super().__init__(f"{layer}:{code}")
        self.layer = layer
        self.code = code
        self.detail = detail


class NaiveRejected(Exception):
    """Наивная реализация отклонила вход (вектор должен её обходить)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class CampaignResult:
    """Итог кампании по одной категории."""

    category: str
    title: str
    outcomes: list[VectorOutcome] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(outcome.passed for outcome in self.outcomes)

    @property
    def failed(self) -> list[VectorOutcome]:
        return [o for o in self.outcomes if not o.passed]

    @property
    def skipped_count(self) -> int:
        return sum(1 for o in self.outcomes if o.skipped)

    def render(self) -> str:
        lines = [
            f"== Кампания «{self.title}»: {len(self.outcomes)} векторов ==",
        ]
        lines += [o.row() for o in self.outcomes]
        verdict = "ЗАЩИТА ВПЕРЕДИ АТАКИ" if self.ok else "ЕСТЬ ДЕФЕКТЫ"
        lines.append(f"Итог: {verdict} (пропусков: {self.skipped_count})")
        return "\n".join(lines)


def render_matrix(title: str, vectors: list[Vector], layers: list[Layer]) -> str:
    """Матрица «вектор × слой»: кто кого останавливает по проекту."""
    width = max((len(v.id) for v in vectors), default=8)
    header = "vector".ljust(width) + " | " + " ".join(layer.id for layer in layers)
    lines = [f"== Матрица «{title}» ==", header, "-" * len(header)]
    for vector in vectors:
        cells = " ".join(
            "X" if layer.id in vector.stopped_by else "." for layer in layers
        )
        lines.append(vector.id.ljust(width) + " | " + cells)
    lines.append("")
    for layer in layers:
        lines.append(f"{layer.id} — {layer.name}: {layer.description}")
    return "\n".join(lines)
