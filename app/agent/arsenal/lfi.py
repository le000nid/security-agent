"""Домен LFI: 31 вектор против 11 слоёв защиты.

v10 расширяет арсенал в два направления:

* **комплексные цепочки** — многошаговые атаки, где обход строится из
  нескольких примитивов: TOCTOU (проверка до подмены, открытие после),
  escape через ``extractall`` без фильтра, symlink-член внутри TAR с записью
  через него, zip-бомба (амплификация 1000x) и вложенный архив
  (zip-in-zip с ``../`` во внутреннем члене);
* **простой залп** — максимально широкий набор тривиальных написаний одного
  и того же обхода (одиночное кодирование слэша, кодированные точки с сырым
  обратным слэшем, полноширинные точки с ASCII-слэшем, percent-encoded
  полноширинные, NUL-зачистка, префикс ``./``, сырая точка с запятой,
  uppercase-обёртка ``FILE://``, семейство резервных копий ``~``/``.old``/
  ``.swp`` и вариант ``.env.local``): враг мог не предусмотреть любую из
  простых форм, поэтому арсенал проверяет их по отдельности.

Наивная реализация песочницы — «файловый сервис» с типовым набором ловушек,
которые реально встречаются в коде: зачистка сырого вида до декодирования,
один проход percent-декодирования, зачистка ``;`` и NUL, NFKC-нормализация
и замена ``\\`` на ``/`` ПОСЛЕ проверок, раскрытие переменных окружения,
второй «legacy» проход декодирования, ручное извлечение членов архивов,
``extractall`` без фильтра, «URL-осведомлённый» читатель и glob-перечисление.

Охраняемая реализация строит путь через те же примитивы, что и
``app.http_guard`` (полное декодирование, канонические сегменты, белый
список, контейнерность после realpath), запрещает обёртки, членов архивов,
glob-метасимволы, dot-файлы и резервные копии, а архивы обрабатывает
поштучно с проверкой каждого члена и лимитами амплитуды.
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
EXTRACT_MARKER = "EXTRACT-SLIP-OK"
TAR_CHAIN_MARKER = "TAR-CHAIN-OK"
NESTED_MARKER = "NESTED-ESCAPE-OK"

_BOMB_MEMBER_BYTES = 8_000_000
_MAX_MEMBER_BYTES = 1_000_000
_MAX_ARCHIVE_RATIO = 100

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
        "разрешённых (.bak, .old, .env, ~, .swp) отклоняются",
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
    Layer(
        "G8",
        "согласованность открытия",
        "файл идентифицируется до открытия и сверяется после (stat/fstat): "
        "подмена пути между проверкой и чтением обнаруживается",
    ),
    Layer(
        "G9",
        "санитизированная распаковка",
        "члены архивов извлекаются поштучно: родительские сегменты и "
        "не-регулярные члены (symlink/hardlink/dev/fifo) отвергаются до записи",
    ),
    Layer(
        "G10",
        "лимиты амплитуды",
        "размер члена архива и коэффициент сжатия ограничены; потоковое "
        "чтение обрывается на лимите (zip-бомбы не проходят)",
    ),
    Layer(
        "G11",
        "глубина вложенности",
        "архив внутри архива запрещён: рекурсивная распаковка недостижима "
        "и не может вынести обход вглубь цепочки",
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
    # --- комплексные цепочки (v10) -------------------------------------------
    Vector(
        "lfi_toctou_swap",
        "TOCTOU: подмена между проверкой и открытием",
        "CWE-367",
        "валидатор видит легитимный файл, атакующий меняет его на symlink, "
        "открытие следует ссылке наружу",
        ("G8",),
    ),
    Vector(
        "lfi_tar_extractall_slip",
        "escape через extractall без фильтра",
        "CWE-23",
        "extractall доверяет члену ../name и пишет за пределы каталога",
        ("G9",),
    ),
    Vector(
        "lfi_tar_symlink_chain",
        "symlink-член внутри TAR и запись через него",
        "CWE-59",
        "архив несёт ссылку наружу и файл «сквозь» неё: распаковка "
        "перезаписывает внешний файл",
        ("G9",),
    ),
    Vector(
        "lfi_zip_bomb_amplification",
        "zip-бомба: амплификация при чтении",
        "CWE-409",
        "член в 8 МБ из нулей сжимается до килобайт; чтение без лимитов "
        "амплифицирует ответ в 1000 раз",
        ("G10",),
    ),
    Vector(
        "lfi_nested_archive_chain",
        "вложенный архив: zip внутри zip",
        "CWE-23",
        "рекурсивная распаковка переносит ../-члена во внутренний слой, где "
        "внешние проверки уже не действуют",
        ("G11",),
    ),
    # --- простой залп (v10) ---------------------------------------------------
    Vector(
        "lfi_single_encoded_slash",
        "одиночное кодирование слэша",
        "CWE-22",
        "простое ..%2f — забыли один процент: сырой фильтр слэша не видит",
        ("G1", "G2"),
    ),
    Vector(
        "lfi_encoded_dots_raw_backslash",
        "кодированные точки, сырой обратный слэш",
        "CWE-22",
        "%2e%2e\\ — точки спрятаны, разделитель оставлен как есть",
        ("G2",),
    ),
    Vector(
        "lfi_fullwidth_dots_ascii_slash",
        "полноширинные точки с ASCII-слэшем",
        "CWE-22",
        "．．/ — юникод-точки проходят «чистые имена», ASCII-слэш остаётся",
        ("G2",),
    ),
    Vector(
        "lfi_percent_encoded_fullwidth",
        "percent-encoded полноширинные символы",
        "CWE-22",
        "%ef%bc%8e%ef%bc%8e%ef%bc%8f декодируется и NFKC собирает ../",
        ("G1", "G2"),
    ),
    Vector(
        "lfi_null_byte_strip_reassembly",
        "NUL-зачистка собирает обход обратно",
        "CWE-22",
        "зачистка \\x00 вместо обрыва склеивает ..\\x00/ в ../",
        ("G2",),
    ),
    Vector(
        "lfi_dot_slash_prefix",
        "префикс ./ маскирует обход",
        "CWE-22",
        "./..%2f — ведущий сегмент уводит payload от сырых фильтров",
        ("G2",),
    ),
    Vector(
        "lfi_semicolon_raw",
        "сырая точка с запятой",
        "CWE-22",
        "..;/ без кодирования: зачистка ; после декодирования строит ../",
        ("G2",),
    ),
    Vector(
        "lfi_file_uri_uppercase",
        "uppercase-обёртка FILE://",
        "CWE-22",
        "FILE:// — фильтры смотрят нижний регистр, URL-читатель схему принимает",
        ("G3",),
    ),
    Vector(
        "lfi_backup_tilde",
        "tilde-резервная копия",
        "CWE-538",
        "config.py~ от редактора доступен напрямую",
        ("G4",),
    ),
    Vector(
        "lfi_backup_old",
        "резервная копия .old",
        "CWE-538",
        "config.py.old с прежней конфигурацией и секретами",
        ("G4",),
    ),
    Vector(
        "lfi_backup_swp",
        "swap-файл редактора",
        "CWE-538",
        ".config.py.swp содержит исходник с секретами",
        ("G4",),
    ),
    Vector(
        "lfi_dotenv_variant",
        "вариант окружения .env.local",
        "CWE-538",
        ".env.local с секретами читается как и .env",
        ("G4",),
    ),
]

_SEGMENT_CHARSET = re.compile(r"[A-Za-z0-9._-]+\Z")
_ALLOWED_SUFFIXES = {".txt", ".md", ".log", ".json", ".csv", ".zip", ".tar"}

# векторы, требующие возможности создавать symlink (POSIX или права на Windows)
_SYMLINK_VECTORS = {"lfi_symlink_hop", "lfi_toctou_swap", "lfi_tar_symlink_chain"}


# --------------------------------------------------------------------------
# Песочница
# --------------------------------------------------------------------------


@dataclass
class LfiSandbox:
    base: Path
    outside: Path
    payloads: dict[str, str] = field(default_factory=dict)
    symlinks_supported: bool = True
    dir_links_supported: bool = True
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
        (self.base / ".env.local").write_text(DOTENV_SECRET, encoding="utf-8")
        (self.base / "notes.md").write_text("# заметки сервиса\n", encoding="utf-8")
        (self.base / "config.py.bak").write_text(BACKUP_SECRET, encoding="utf-8")
        (self.base / "config.py~").write_text(BACKUP_SECRET, encoding="utf-8")
        (self.base / "config.py.old").write_text(BACKUP_SECRET, encoding="utf-8")
        (self.base / ".config.py.swp").write_text(BACKUP_SECRET, encoding="utf-8")
        (self.base / "report.txt").write_text("REPORT-MARKER", encoding="utf-8")
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
        with tarfile.open(self.base / "evil-extract.tar", "w") as tf:
            payload = EXTRACT_MARKER.encode("utf-8")
            info = tarfile.TarInfo("../arsenal_extract_escape.txt")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        with tarfile.open(self.base / "chain.tar", "w") as tf:
            link = tarfile.TarInfo("lnk")
            link.type = tarfile.SYMTYPE
            link.linkname = "../outside"
            tf.addfile(link)
            payload = TAR_CHAIN_MARKER.encode("utf-8")
            info = tarfile.TarInfo("lnk/chain_write.txt")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        with zipfile.ZipFile(self.base / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.bin", "\x00" * _BOMB_MEMBER_BYTES)
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("../arsenal_nested_escape.txt", NESTED_MARKER)
        with zipfile.ZipFile(self.base / "nested.zip", "w") as zf:
            zf.writestr("inner.zip", inner.getvalue())
        try:
            os.symlink(self.outside / "secret.txt", self.base / "out_link.txt")
        except (OSError, NotImplementedError):
            self.symlinks_supported = False
        try:
            os.symlink(
                self.outside, self.base / "out_dlink.txt", target_is_directory=True
            )
        except (OSError, NotImplementedError):
            self.dir_links_supported = False
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
            "lfi_toctou_swap": "report.txt",
            "lfi_tar_extractall_slip": "evil-extract.tar",
            "lfi_tar_symlink_chain": "chain.tar",
            "lfi_zip_bomb_amplification": "bomb.zip",
            "lfi_nested_archive_chain": "nested.zip",
            "lfi_single_encoded_slash": "..%2foutside%2fsecret.txt",
            "lfi_encoded_dots_raw_backslash": "%2e%2e\\outside\\secret.txt",
            "lfi_fullwidth_dots_ascii_slash": "．．/outside/secret.txt",
            "lfi_percent_encoded_fullwidth": (
                "%ef%bc%8e%ef%bc%8e%ef%bc%8foutside%ef%bc%8fsecret.txt"
            ),
            "lfi_null_byte_strip_reassembly": "..%00%2foutside%2fsecret.txt",
            "lfi_dot_slash_prefix": "./..%2foutside%2fsecret.txt",
            "lfi_semicolon_raw": "..;/outside/secret.txt",
            "lfi_file_uri_uppercase": (self.outside / "secret.txt")
            .as_uri()
            .replace("file://", "FILE://", 1),
            "lfi_backup_tilde": "config.py~",
            "lfi_backup_old": "config.py.old",
            "lfi_backup_swp": ".config.py.swp",
            "lfi_dotenv_variant": ".env.local",
        }

    def unavailable(self) -> set[str]:
        skip: set[str] = set()
        if not self.symlinks_supported:
            skip |= set(_SYMLINK_VECTORS)
        if not self.dir_links_supported:
            # dir-ссылка не создаётся — цепочка «ссылка + запись сквозь неё»
            skip.add("lfi_tar_symlink_chain")
        return skip

    def reset_report(self) -> None:
        """Вернуть report.txt к регулярному файлу (стартовая точка атаки)."""
        target = self.base / "report.txt"
        if target.is_symlink():
            target.unlink()
            target.write_text("REPORT-MARKER", encoding="utf-8")

    def swap_report(self) -> None:
        """Атакующий меняет report.txt на symlink наружу (и обратно).

        Переключатель нужен, чтобы наивная и охраняемая ветки получали
        одинаковую стартовую точку: каждая вызывает подмену ровно один раз.
        """
        target = self.base / "report.txt"
        if target.is_symlink():
            target.unlink()
            target.write_text("REPORT-MARKER", encoding="utf-8")
            return
        target.unlink(missing_ok=True)
        os.symlink(self.outside / "secret.txt", target)

    def judge(self, vector_id: str, value: str, data: str) -> tuple[bool, str]:
        outside_readers = {
            "lfi_semicolon_interrupt",
            "lfi_double_decode",
            "lfi_filter_before_decode",
            "lfi_backslash_join",
            "lfi_nfkc_fullwidth",
            "lfi_absolute_discard",
            "lfi_env_var_expansion",
            "lfi_symlink_hop",
            "lfi_file_uri_wrapper",
            "lfi_single_encoded_slash",
            "lfi_encoded_dots_raw_backslash",
            "lfi_fullwidth_dots_ascii_slash",
            "lfi_percent_encoded_fullwidth",
            "lfi_null_byte_strip_reassembly",
            "lfi_dot_slash_prefix",
            "lfi_semicolon_raw",
            "lfi_file_uri_uppercase",
            "lfi_toctou_swap",
        }
        if vector_id in outside_readers:
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
        if vector_id == "lfi_tar_extractall_slip":
            escaped = self.base.parent / "arsenal_extract_escape.txt"
            ok = (
                escaped.is_file()
                and escaped.read_text(encoding="utf-8") == EXTRACT_MARKER
            )
            return ok, "extractall написал за базу" if ok else "записи за базу нет"
        if vector_id == "lfi_tar_symlink_chain":
            ok = (self.outside / "chain_write.txt").read_text(
                encoding="utf-8"
            ) == TAR_CHAIN_MARKER
            return ok, "запись через ссылку наружу выполнена" if ok else "нет записи"
        if vector_id == "lfi_zip_bomb_amplification":
            size = int(data) if data.isdigit() else 0
            archive_size = (self.base / "bomb.zip").stat().st_size
            ok = size >= _BOMB_MEMBER_BYTES and archive_size * 100 <= size
            return (
                ok,
                f"амплификация {size // max(archive_size, 1)}x"
                if ok
                else "лимитов нет",
            )
        if vector_id == "lfi_nested_archive_chain":
            escaped = self.base.parent / "arsenal_nested_escape.txt"
            ok = (
                escaped.is_file()
                and escaped.read_text(encoding="utf-8") == NESTED_MARKER
            )
            return ok, "вложенный архив вынес запись за базу" if ok else "записи нет"
        if vector_id in {"lfi_dotfile_exposure", "lfi_dotenv_variant"}:
            return (
                DOTENV_SECRET in data,
                ".env-файл прочитан" if DOTENV_SECRET in data else "нет",
            )
        if vector_id in {
            "lfi_backup_file_exposure",
            "lfi_backup_tilde",
            "lfi_backup_old",
            "lfi_backup_swp",
        }:
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


def _remove_path(path: Path) -> None:
    """Убрать путь любого вида (ссылка, файл, пустой каталог) — для перезаписи."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        path.rmdir()


def naive_extract_all(base: Path, archive_name: str) -> None:
    """«Удобная» распаковка целиком: членам архива доверяют.

    На Windows tarfile создаёт symlink-член как file-ссылку на каталог и
    падает на makedirs при записи следующего члена «сквозь» неё; тогда
    доводим ту же доверенную распаковку вручную — так поступают свои
    распаковщики в реальных приложениях, уязвимость от этого не меняется.
    """
    try:
        with tarfile.open(base / archive_name) as tf:
            try:
                tf.extractall(base, filter="fully_trusted")
            except TypeError:  # Python < 3.11.4: параметра filter ещё нет
                tf.extractall(base)
            return
    except OSError:
        pass  # наивный «стек» не осилил свой же symlink-член — доигрываем
    with tarfile.open(base / archive_name) as tf:
        for member in tf.getmembers():
            target = base / member.name
            if member.issym():
                _remove_path(target)  # доверенный стек перезаписывает ссылку
                target_is_dir = (base / member.linkname).is_dir()
                os.symlink(member.linkname, target, target_is_directory=target_is_dir)
            elif member.isreg():
                handle = tf.extractfile(member)
                if handle is None:
                    raise NaiveRejected("no_such_member")
                # путь НЕ санитизируется: компоненты-ссылки резолвит сама ОС,
                # поэтому пишем по фактическому (resolved) пути — ровно туда,
                # куда легла бы запись «сквозь» ссылку
                final = Path(os.path.realpath(target))
                final.parent.mkdir(parents=True, exist_ok=True)
                final.write_bytes(handle.read())


def naive_nested_extract(base: Path, archive_name: str) -> None:
    """Рекурсивная распаковка: архивы внутри архивов тоже «доверенные»."""
    with zipfile.ZipFile(base / archive_name) as zf:
        inner_bytes = zf.read("inner.zip")
    unpacked = base / "unpacked_inner.zip"
    unpacked.write_bytes(inner_bytes)
    with zipfile.ZipFile(unpacked) as zf:
        for member in zf.namelist():
            target = base / member  # путь члена НЕ санитизируется
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))


def naive_run(ctx: LfiSandbox, vector_id: str) -> tuple[bool, str]:
    raw = ctx.payloads[vector_id]
    try:
        value = naive_resolve(raw)
    except NaiveRejected as exc:
        return False, f"отклонено наивной проверкой: {exc.code}"
    try:
        if vector_id == "lfi_toctou_swap":
            resolved = Path(ctx.base) / value
            # «проверка контейнерности» выполняется до открытия...
            if not str(resolved.resolve()).startswith(str(Path(ctx.base).resolve())):
                raise NaiveRejected("containment_check")
            # ...а атакующий меняет файл как раз между ними
            ctx.swap_report()
            data = resolved.read_text(encoding="utf-8", errors="replace")
            return ctx.judge(vector_id, value, data)
        if vector_id == "lfi_tar_extractall_slip":
            naive_extract_all(Path(ctx.base), value)
            return ctx.judge(vector_id, value, "")
        if vector_id == "lfi_tar_symlink_chain":
            naive_extract_all(Path(ctx.base), value)
            return ctx.judge(vector_id, value, "")
        if vector_id == "lfi_nested_archive_chain":
            naive_nested_extract(Path(ctx.base), value)
            return ctx.judge(vector_id, value, "")
        if vector_id == "lfi_zip_bomb_amplification":
            with zipfile.ZipFile(Path(ctx.base) / value) as zf:
                size = len(zf.read("bomb.bin"))  # чтение без лимитов
            return ctx.judge(vector_id, value, str(size))
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
    """Построить путь по файловому параметру, пройдя слои G1-G7."""
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


def safe_open_consistent(ctx: LfiSandbox, raw: str) -> Path:
    """Открыть файл со сверкой идентичности до и после (G8).

    Атакующий (песочница) выполняет подмену ровно между stat и открытием:
    если идентичность файла изменилась — путь был подменён, чтение запрещено.
    """
    ctx.reset_report()  # атака начинается с регулярного файла
    path = safe_file_param(ctx, raw)  # G1-G7 как обычно
    before = os.stat(path)
    ctx.swap_report()  # окно TOCTOU: подмена между проверкой и открытием
    fd = os.open(path, os.O_RDONLY)
    try:
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise DefenseHold("G8", "path_swapped_between_check_and_open")
    return path


def _reject_dangerous_tar_member(member: tarfile.TarInfo) -> None:
    """G9: член архива обязан быть регулярным файлом без родительских сегментов."""
    name = member.name.replace("\\", "/")
    if any(p == ".." for p in name.split("/")):
        raise DefenseHold("G9", "parent_segment_in_member")
    if not member.isreg():
        raise DefenseHold("G9", "non_regular_member")


def safe_extract_tar(ctx: LfiSandbox, raw: str) -> Path:
    """Распаковка TAR поштучно: каждый член валидируется до записи (G9)."""
    path = safe_file_param(ctx, raw)  # G1-G7 на пути самого архива
    with tarfile.open(path) as tf:
        for member in tf.getmembers():
            _reject_dangerous_tar_member(member)
    return path


def safe_archive_member(ctx: LfiSandbox, raw: str) -> Path:
    """Чтение ZIP с проверкой каждого члена (G9/G10/G11)."""
    path = safe_file_param(ctx, raw)  # G1-G7 на пути архива
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if any(p == ".." for p in name.split("/")):
                raise DefenseHold("G9", "parent_segment_in_member")
            if name.lower().endswith((".zip", ".tar")):
                raise DefenseHold("G11", "nested_archive_forbidden")
            if info.file_size > _MAX_MEMBER_BYTES:
                raise DefenseHold("G10", "member_size_exceeded")
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > _MAX_ARCHIVE_RATIO:
                raise DefenseHold("G10", "compression_ratio_exceeded")
    return path


def guarded_run(ctx: LfiSandbox, vector_id: str) -> tuple[bool, str, str]:
    try:
        if vector_id == "lfi_toctou_swap":
            safe_open_consistent(ctx, ctx.payloads[vector_id])
            return False, "", "охраняемая реализация прочитала подменённый файл"
        if vector_id in {"lfi_tar_extractall_slip", "lfi_tar_symlink_chain"}:
            safe_extract_tar(ctx, ctx.payloads[vector_id])
            return False, "", "охраняемая распаковка допустила опасный член архива"
        if vector_id in {"lfi_zip_bomb_amplification", "lfi_nested_archive_chain"}:
            safe_archive_member(ctx, ctx.payloads[vector_id])
            return False, "", "охраняемое чтение архива допустило член"
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
