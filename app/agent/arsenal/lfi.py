"""Домен LFI: 14 векторов против 7 слоёв защиты.

Наивная реализация песочницы — «файловый сервис» с типовым набором ловушек,
которые реально встречаются в коде: зачистка сырого вида до декодирования,
один проход percent-декодирования, зачистка ``;`` и NUL, NFKC-нормализация
и замена ``\\`` на ``/`` ПОСЛЕ проверок, раскрытие переменных окружения,
второй «legacy» проход декодирования, ручное извлечение членов архивов,
«URL-осведомлённый» читатель и glob-перечисление. Каждый вектор обходит
ровно одну такую ловушку и читает файл за пределами базы.

Охраняемая реализация строит путь через те же примитивы, что и
``app.http_guard`` (полное декодирование, канонические сегменты, белый
список, контейнерность после realpath) и запрещает обёртки, членов
архивов, glob-метасимволы, dot-файлы и резервные копии.
"""

from __future__ import annotations

import glob
import io
import os
import re
import tarfile
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote, unquote
from urllib.request import urlopen

from app.agent.arsenal.core import (
    CampaignResult,
    DefenseHold,
    Layer,
    NaiveRejected,
    Vector,
    VectorOutcome,
)
from app.http_guard import contained_path, fully_decode, no_scheme

INSIDE_SECRET = "ARSENAL-INSIDE-SECRET"
DOTENV_SECRET = "ARSENAL_DOTENV_KEY=inside"
BACKUP_SECRET = "BACKUP-CONFIG-SECRET"
OUTSIDE_SECRET = "ARSENAL-OUTSIDE-SECRET"
ZIP_MARKER = "ZIP-ESCAPE-OK"
TAR_MARKER = "TAR-ESCAPE-OK"

# --------------------------------------------------------------------------
# Слои защиты (охраняемая реализация)
# --------------------------------------------------------------------------

LAYERS = [
    Layer(
        "G1",
        "декодирование до фикс-поинта",
        "percent-декодирование повторяется до стабильности до любых проверок; "
        "валидатор всегда видит финальную форму значения",
    ),
    Layer(
        "G2",
        "канонические сегменты",
        "NFKC-нормализация до проверок, запрет родительских сегментов, "
        "абсолютных подсказок и привода диска",
    ),
    Layer(
        "G3",
        "запрет обёрток",
        "URI-схемы (php://, file://, data:), члены архивов (#) и "
        "glob-метасимволы (*) в файловом параметре запрещены",
    ),
    Layer(
        "G4",
        "белый список сегментов",
        "сегменты только [A-Za-z0-9._-]; dot-файлы и суффиксы вне "
        "разрешённых (.bak, .old, .env) отклоняются",
    ),
    Layer(
        "G5",
        "запрет раскрытий",
        "переменные окружения ($) и остаточные проценты после декодирования "
        "недопустимы в файловом параметре",
    ),
    Layer(
        "G6",
        "контейнерность после realpath",
        "путь собирается и разрешается (symlink-хопы учитываются), затем "
        "доказывается, что результат внутри базы",
    ),
    Layer(
        "G7",
        "заморозка порядка",
        "после валидации каноническая форма не мутирует; относительный "
        "результат перепроверяется теми же правилами",
    ),
]

VECTORS = [
    Vector(
        "lfi_semicolon_interrupt",
        "прерывание обхода через ;",
        "CWE-22",
        "зачистка ;jsessionid выполняется после декодирования и собирает "
        "«..;/» обратно в «../»",
        ("G2",),
    ),
    Vector(
        "lfi_double_decode",
        "двойное процент-кодирование",
        "CWE-22",
        "второй legacy-проход декодирования раскрывает %252e%252e%252f в ../",
        ("G1", "G2"),
    ),
    Vector(
        "lfi_filter_before_decode",
        "санитизация до декодирования",
        "CWE-22",
        "фильтр видит %2e%2e%2f, а open получает уже декодированный ../",
        ("G1", "G2"),
    ),
    Vector(
        "lfi_backslash_join",
        "обратный слэш на стыке",
        "CWE-22",
        "замена \\ на / выполняется после зачистки и строит ../ из ..\\",
        ("G2",),
    ),
    Vector(
        "lfi_nfkc_fullwidth",
        "полноширинная NFKC-нормализация",
        "CWE-22",
        "．．／ нормализуется в ../ после всех проверок",
        ("G2",),
    ),
    Vector(
        "lfi_absolute_discard",
        "абсолютный путь отбрасывает базу",
        "CWE-22",
        "Path(base) / '/abs' возвращает абсолютный путь, игнорируя базу",
        ("G2", "G6"),
    ),
    Vector(
        "lfi_env_var_expansion",
        "раскрытие переменной окружения",
        "CWE-22",
        "expandvars «для удобства» подставляет путь наружу после санитизации",
        ("G5",),
    ),
    Vector(
        "lfi_symlink_hop",
        "symlink-хоп из базы",
        "CWE-59",
        "ссылка внутри базы указывает на файл снаружи; realpath не проверяется",
        ("G6",),
    ),
    Vector(
        "lfi_zip_member_write",
        "обход через член ZIP-архива",
        "CWE-23",
        "ручная запись члена архива ../name без санитизации пути",
        ("G3",),
    ),
    Vector(
        "lfi_tar_member_write",
        "обход через член TAR-архива",
        "CWE-23",
        "ручная запись члена архива ../name без санитизации пути",
        ("G3",),
    ),
    Vector(
        "lfi_file_uri_wrapper",
        "file:// обёртка «URL-читателя»",
        "CWE-22",
        "осведомлённый о URL читатель открывает локальный файл по file://",
        ("G3",),
    ),
    Vector(
        "lfi_dotfile_exposure",
        "чтение dot-файла",
        "CWE-538",
        ".env с секретами свободно читается по имени",
        ("G4",),
    ),
    Vector(
        "lfi_backup_file_exposure",
        "чтение резервной копии",
        "CWE-538",
        "config.py.bak с исходником и секретами доступен напрямую",
        ("G4",),
    ),
    Vector(
        "lfi_glob_enumeration",
        "перечисление через glob-шаблон",
        "CWE-22",
        "шаблон * в файловом параметре перечисляет содержимое базы",
        ("G3", "G4"),
    ),
]

_SEGMENT_CHARSET = re.compile(r"[A-Za-z0-9._-]+\Z")
_ALLOWED_SUFFIXES = {".txt", ".md", ".log", ".json", ".csv", ".zip", ".tar"}


# --------------------------------------------------------------------------
# Песочница
# --------------------------------------------------------------------------


@dataclass
class LfiSandbox:
    base: Path
    outside: Path
    payloads: dict[str, str] = field(default_factory=dict)
    symlinks_supported: bool = True
    _temp: TemporaryDirectory | None = None
    _env_name: str = "ARSENAL_OUTSIDE_DIR"

    def __enter__(self) -> "LfiSandbox":
        self._temp = TemporaryDirectory(prefix="arsenal-lfi-")
        root = Path(self._temp.name)
        self.base = root / "base"
        self.outside = root / "outside"
        (self.base / "logs").mkdir(parents=True)
        self.outside.mkdir(parents=True)
        (self.base / "secret.txt").write_text(INSIDE_SECRET, encoding="utf-8")
        (self.base / ".env").write_text(DOTENV_SECRET, encoding="utf-8")
        (self.base / "notes.md").write_text("# заметки сервиса\n", encoding="utf-8")
        (self.base / "config.py.bak").write_text(BACKUP_SECRET, encoding="utf-8")
        (self.base / "logs" / "app.log").write_text(
            "service log line\n", encoding="utf-8"
        )
        (self.outside / "secret.txt").write_text(OUTSIDE_SECRET, encoding="utf-8")
        with zipfile.ZipFile(self.base / "docs.zip", "w") as zf:
            zf.writestr(zipfile.ZipInfo("../arsenal_zip_escape.txt"), ZIP_MARKER)
        with tarfile.open(self.base / "docs.tar", "w") as tf:
            info = tarfile.TarInfo("../arsenal_tar_escape.txt")
            payload = TAR_MARKER.encode("utf-8")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        try:
            os.symlink(self.outside / "secret.txt", self.base / "out_link.txt")
        except (OSError, NotImplementedError):
            self.symlinks_supported = False
        os.environ[self._env_name] = str(self.outside)
        self._build_payloads()
        return self

    def __exit__(self, *exc) -> None:
        os.environ.pop(self._env_name, None)
        if self._temp is not None:
            self._temp.cleanup()

    def _build_payloads(self) -> None:
        outside_file = quote(str(self.outside / "secret.txt"), safe="")
        if os.name == "nt":
            env_ref = f"%{self._env_name}%"
        else:
            env_ref = f"${self._env_name}"
        self.payloads = {
            "lfi_semicolon_interrupt": "..%3b%2foutside%2fsecret.txt",
            "lfi_double_decode": "..%252foutside%2fsecret.txt",
            "lfi_filter_before_decode": "%2e%2e%2foutside%2fsecret.txt",
            "lfi_backslash_join": "..%5coutside%5csecret.txt",
            "lfi_nfkc_fullwidth": "．．／outside／secret.txt",
            "lfi_absolute_discard": outside_file,
            "lfi_env_var_expansion": f"{env_ref}/secret.txt",
            "lfi_symlink_hop": "out_link.txt",
            "lfi_zip_member_write": "docs.zip#%2e%2e%2farsenal_zip_escape.txt",
            "lfi_tar_member_write": "docs.tar#%2e%2e%2farsenal_tar_escape.txt",
            "lfi_file_uri_wrapper": (self.outside / "secret.txt").as_uri(),
            "lfi_dotfile_exposure": ".env",
            "lfi_backup_file_exposure": "config.py.bak",
            "lfi_glob_enumeration": "*",
        }

    def unavailable(self) -> set[str]:
        return set() if self.symlinks_supported else {"lfi_symlink_hop"}

    def judge(self, vector_id: str, value: str, data: str) -> tuple[bool, str]:
        if vector_id in {
            "lfi_semicolon_interrupt",
            "lfi_double_decode",
            "lfi_filter_before_decode",
            "lfi_backslash_join",
            "lfi_nfkc_fullwidth",
            "lfi_absolute_discard",
            "lfi_env_var_expansion",
            "lfi_symlink_hop",
            "lfi_file_uri_wrapper",
        }:
            return (
                OUTSIDE_SECRET in data,
                "наружный файл прочитан" if OUTSIDE_SECRET in data else "не тот файл",
            )
        if vector_id == "lfi_zip_member_write":
            escaped = self.base.parent / "arsenal_zip_escape.txt"
            ok = escaped.is_file() and escaped.read_text(encoding="utf-8") == ZIP_MARKER
            return ok, "член архива записан за базу" if ok else "записи за базу нет"
        if vector_id == "lfi_tar_member_write":
            escaped = self.base.parent / "arsenal_tar_escape.txt"
            ok = escaped.is_file() and escaped.read_text(encoding="utf-8") == TAR_MARKER
            return ok, "член архива записан за базу" if ok else "записи за базу нет"
        if vector_id == "lfi_dotfile_exposure":
            return (
                DOTENV_SECRET in data,
                ".env прочитан" if DOTENV_SECRET in data else "нет",
            )
        if vector_id == "lfi_backup_file_exposure":
            return (
                BACKUP_SECRET in data,
                "резервная копия прочитана" if BACKUP_SECRET in data else "нет",
            )
        if vector_id == "lfi_glob_enumeration":
            names = [n for n in data.split(", ") if n]
            ok = len(names) >= 2 and any(n.endswith("secret.txt") for n in names)
            return (
                ok,
                f"перечислено {len(names)} файлов" if ok else "перечисление пусто",
            )
        return False, "неизвестный вектор"


def build_context() -> LfiSandbox:
    return LfiSandbox(base=Path("."), outside=Path("."))


# --------------------------------------------------------------------------
# Наивная реализация
# --------------------------------------------------------------------------


def naive_resolve(raw: str) -> str:
    """Типовой «защищённый» резолвер с набором реальных ловушек."""
    v = raw
    if "../" in v or "..\\" in v or v.startswith("/") or v.startswith("~"):
        raise NaiveRejected("raw_traversal_or_absolute")
    # зачистка выполняется ДО декодирования — на сыром виде
    v = v.replace("../", "").replace("..\\", "")
    v = unquote(v)  # один проход декодирования
    v = v.replace(";", "").replace("\x00", "")  # jsessionid и нулевые байты
    v = unicodedata.normalize("NFKC", v)  # «юникод-дружественные имена»
    v = v.replace("\\", "/")  # windows-совместимость на стыке
    v = os.path.expandvars(v)  # «удобство»: раскрытие переменных окружения
    v = unquote(v)  # legacy-хранилище: второй проход декодирования
    return v


def naive_archive_member(base: Path, archive_name: str, member: str) -> str:
    archive_path = base / archive_name
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as zf:
            data = zf.read(member)
    elif archive_path.suffix == ".tar":
        with tarfile.open(archive_path) as tf:
            handle = tf.extractfile(member)
            if handle is None:
                raise NaiveRejected("no_such_member")
            data = handle.read()
    else:
        raise NaiveRejected("unknown_archive")
    # ручная запись члена архива — путь НЕ санитизируется
    target = base / member
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data.decode("utf-8")


def naive_run(ctx: LfiSandbox, vector_id: str) -> tuple[bool, str]:
    raw = ctx.payloads[vector_id]
    try:
        value = naive_resolve(raw)
    except NaiveRejected as exc:
        return False, f"отклонено наивной проверкой: {exc.code}"
    try:
        if "://" in value:
            with urlopen(value, timeout=5) as handle:  # «URL-осведомлённый» читатель
                data = handle.read().decode("utf-8", "replace")
        elif "#" in value:
            archive, member = value.split("#", 1)
            data = naive_archive_member(Path(ctx.base), archive, member)
        elif "*" in value or "?" in value:
            data = ", ".join(sorted(glob.glob(str(Path(ctx.base) / value))))
        else:
            data = (Path(ctx.base) / value).read_text(
                encoding="utf-8", errors="replace"
            )
    except NaiveRejected as exc:
        return False, f"наивный обработчик отклонил: {exc.code}"
    except OSError as exc:
        return False, f"чтение не удалось: {exc.__class__.__name__}"
    return ctx.judge(vector_id, value, data)


# --------------------------------------------------------------------------
# Охраняемая реализация
# --------------------------------------------------------------------------


def safe_file_param(ctx: LfiSandbox, raw: str) -> Path:
    """Построить путь по файловому параметру, пройдя все семь слоёв."""
    value = fully_decode(raw)  # G1: фикс-поинт декодирования до проверок
    if "$" in value or "%" in value:  # G5: раскрытия и остаточные проценты
        raise DefenseHold("G5", "expansion_or_residual_percent")
    value = unicodedata.normalize("NFKC", value)  # G2: канонизация до проверок
    if re.match(r"^[a-zA-Z]:", value) or value.startswith(("/", "\\", "~")):
        raise DefenseHold("G2", "absolute_hint")  # G2: абсолютные подсказки
    parts = [p for p in re.split(r"[\\/]+", value) if p not in ("", ".")]
    if any(p.startswith("..") for p in parts):
        raise DefenseHold("G2", "parent_segment")  # G2: родительские сегменты
    if "://" in value or "#" in value or "*" in value or "?" in value:
        raise DefenseHold("G3", "wrapper_or_member_or_glob")  # G3
    try:
        no_scheme(value)
    except ValueError as exc:
        raise DefenseHold("G3", str(exc)) from exc  # G3: URI-обёртки
    if any(not _SEGMENT_CHARSET.fullmatch(p) for p in parts):
        raise DefenseHold("G4", "segment_charset")  # G4: белый список символов
    if any(p.startswith(".") for p in parts):
        raise DefenseHold("G4", "dotfile_forbidden")  # G4: dot-файлы
    suffix = Path(parts[-1]).suffix.lower() if parts else ""
    if suffix not in _ALLOWED_SUFFIXES:
        raise DefenseHold("G4", "suffix_not_allowed")  # G4: суффиксы
    try:
        resolved = contained_path(ctx.base, *parts)  # G6: realpath-контейнерность
    except ValueError as exc:
        raise DefenseHold("G6", str(exc)) from exc
    rel = resolved.relative_to(Path(ctx.base).resolve())
    if any(p.startswith("..") or p.startswith(".") for p in rel.parts):
        raise DefenseHold("G7", "post_validation_mutation")  # G7: заморозка
    return resolved


def guarded_run(ctx: LfiSandbox, vector_id: str) -> tuple[bool, str, str]:
    try:
        safe_file_param(ctx, ctx.payloads[vector_id])
    except DefenseHold as hold:
        return True, hold.layer, hold.code
    return False, "", "охраняемая реализация допустила путь"


# --------------------------------------------------------------------------
# Кампании и матрица
# --------------------------------------------------------------------------


def campaign() -> CampaignResult:
    result = CampaignResult(category="lfi", title="LFI: локальное включение файлов")
    with build_context() as ctx:
        for vector in VECTORS:
            if vector.id in ctx.unavailable():
                result.outcomes.append(
                    VectorOutcome(
                        vector,
                        None,
                        "платформа не поддерживает symlink",
                        None,
                        "",
                        "пропуск",
                    )
                )
                continue
            attack_ok, attack_detail = naive_run(ctx, vector.id)
            hold_ok, hold_layer, hold_detail = guarded_run(ctx, vector.id)
            result.outcomes.append(
                VectorOutcome(
                    vector, attack_ok, attack_detail, hold_ok, hold_layer, hold_detail
                )
            )
    return result
