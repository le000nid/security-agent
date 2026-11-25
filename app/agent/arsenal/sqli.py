"""Домен SQLI: 14 векторов против 6 слоёв защиты на настоящей SQLite.

Наивная реализация песочницы — «микросервис сноркета» из четырёх операций,
каждая со своей ловушкой:

* ``naive_legacy_login`` — f-string SQL без всякой обработки (endpoint
  «оставлен для совместимости»);
* ``naive_login`` — фильтр кавычек, NFKC-нормализация «юникод-имён» и
  percent-декодирование, причём ровно в таком порядке (фильтр видит сырой
  вид, SQL — декодированный);
* ``naive_search`` / ``naive_list_users`` / ``naive_user_lookup`` — сырая
  интерполяция в LIKE / ORDER BY / сравнение;
* ``naive_admin_tool`` — executescript произвольного входа (stacked
  statements, PRAGMA, ATTACH);
* ``naive_register``/``naive_profile`` — second-order: значение из БД
  считается доверенным и попадает в SQL без обработки.

База — настоящий SQLite-файл в каталоге песочницы; каждый вектор реально
меняет результат запроса (вход под admin, утечка токенов, запись файла
через ATTACH). Охраняемая реализация использует параметризацию, белый
список идентификаторов, канонизацию входа с запретом quote-класса,
ESCAPE-маскирование LIKE и повторную проверку значений из БД.
"""

from __future__ import annotations

import re
import sqlite3
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import unquote

from app.agent.arsenal.core import (
    CampaignResult,
    DefenseHold,
    Layer,
    NaiveRejected,
    Vector,
    VectorOutcome,
)
from app.http_guard import fully_decode

ADMIN_NAME = "admin"
ADMIN_PASS = "ARSENAL-DB-SECRET"
GUEST_NAME = "guest"
GUEST_PASS = "guestpass"
ADMIN_TOKEN = "ARSENAL-TOKEN-ADMIN"
GUEST_TOKEN = "ARSENAL-TOKEN-GUEST"
NOTE_SECRET = "ARSENAL-DB-SECRET"
NOTE_TEXT = f"reset phrase: {NOTE_SECRET}"
ATTACH_MARKER = "SQLI-WRITE"

LAYERS = [
    Layer(
        "Q1",
        "параметризация и закрытый реестр",
        "все запросы строятся только из шаблонов с плейсхолдерами; сырые и "
        "legacy-эндпоинты удалены из реестра операций",
    ),
    Layer(
        "Q2",
        "allowlist идентификаторов",
        "ORDER BY и имена колонок выбираются только из белого списка "
        "известных столбцов, никогда из входа",
    ),
    Layer(
        "Q3",
        "одно statement, никакой DDL из входа",
        "execute() вместо executescript(); административные операции — "
        "фиксированный реестр, PRAGMA/ATTACH/CREATE из входа недостижимы",
    ),
    Layer(
        "Q4",
        "канонизация входа",
        "декодирование до фикс-поинта, NFKC-нормализация, затем запрет "
        "quote-класса, комментариев и blob/char-конструкций",
    ),
    Layer(
        "Q5",
        "ESCAPE-маскирование LIKE",
        "пользовательский шаблон маскируется (\\, %, _) и уходит в LIKE с "
        "явным ESCAPE — wildcards теряют силу",
    ),
    Layer(
        "Q6",
        "повторная проверка значений из БД",
        "second-order: значение, прочитанное из базы, перед повторным "
        "использованием в SQL проходит те же проверки, что и вход",
    ),
]

VECTORS = [
    Vector(
        "sqli_classic_tautology",
        "классическая тавтология",
        "CWE-89",
        "' OR 1=1-- в f-string логина отменяет пароль",
        ("Q1", "Q4"),
    ),
    Vector(
        "sqli_comment_auth_bypass",
        "вход комментарием",
        "CWE-89",
        "admin'-- обрезает проверку пароля",
        ("Q1", "Q4"),
    ),
    Vector(
        "sqli_decode_after_filter",
        "декодирование после фильтра",
        "CWE-89",
        "%27 проходит фильтр кавычек и раскрывается перед встраиванием",
        ("Q4", "Q1"),
    ),
    Vector(
        "sqli_nfkc_fullwidth_quote",
        "полноширинная кавычка через NFKC",
        "CWE-89",
        "＇ нормализуется в ' после фильтра и ломает строку SQL",
        ("Q4",),
    ),
    Vector(
        "sqli_second_order_stored",
        "second-order через сохранённое значение",
        "CWE-89",
        "raw-имя при регистрации выстреливает в f-string запроса токенов",
        ("Q4", "Q6"),
    ),
    Vector(
        "sqli_like_wildcard_disclosure",
        "утечка через wildcard LIKE",
        "CWE-89",
        "% в поиске возвращает все заметки, включая секретную",
        ("Q5",),
    ),
    Vector(
        "sqli_order_by_case_blind",
        "boolean-blind в ORDER BY",
        "CWE-89",
        "CASE WHEN подзапрос в сортировке отвечает на вопросы о данных",
        ("Q2",),
    ),
    Vector(
        "sqli_pragma_recon",
        "PRAGMA-рекогносцировка",
        "CWE-89",
        "executescript входа меняет режим журнала и раскрывает устройство БД",
        ("Q3",),
    ),
    Vector(
        "sqli_attach_file_write",
        "запись файла через ATTACH",
        "CWE-89",
        "ATTACH DATABASE создаёт файл в выбранном атакующим месте",
        ("Q3",),
    ),
    Vector(
        "sqli_hex_blob_smuggle",
        "blob-литерал вместо кавычек",
        "CWE-89",
        "CAST(x'61646d696e' AS TEXT) — имя admin без единой кавычки",
        ("Q1", "Q4"),
    ),
    Vector(
        "sqli_char_runtime_string",
        "сборка строки функцией char()",
        "CWE-89",
        "char(97,100,109,105,110) строит 'admin' в рантайме, минуя фильтры",
        ("Q1", "Q4"),
    ),
    Vector(
        "sqli_cte_exfil",
        "выгрузка секрета через CTE",
        "CWE-89",
        "WITH-подзапрос достаёт пароль администратора в результат",
        ("Q1", "Q4"),
    ),
    Vector(
        "sqli_inline_comment_split",
        "разбивка комментариями /**/",
        "CWE-89",
        "x'/**/OR/**/name='admin обходит фильтры пробелов и слов",
        ("Q1", "Q4"),
    ),
    Vector(
        "sqli_boolean_blind_substr",
        "посимвольная утечка через LIKE",
        "CWE-89",
        "ORACLE: (SELECT substr(note,1,1)…)='r' отвечает да/нет по одной "
        "букве за запрос",
        ("Q4", "Q1", "Q5"),
    ),
]

SQLI_OPS_ALLOWED = ("journal_mode", "vacuum")
SORT_COLUMNS = {"name": "name", "role": "role"}
_SQL_QUOTE_CLASS = ("'", '"', "`", ";")
_SQL_LITERAL_PATTERNS = (
    re.compile(r"\bx'[0-9a-fA-F]*'", re.IGNORECASE),
    re.compile(r"\bchar\s*\(", re.IGNORECASE),
)


# --------------------------------------------------------------------------
# Песочница
# --------------------------------------------------------------------------


@dataclass
class SqliSandbox:
    conn: sqlite3.Connection
    outside_db: Path
    payloads: dict[str, str]
    _temp: TemporaryDirectory | None = None

    def __enter__(self) -> "SqliSandbox":
        return self

    def __exit__(self, *exc) -> None:
        self.conn.close()
        if self._temp is not None:
            self._temp.cleanup()

    def unavailable(self) -> set[str]:
        return set()


def build_context() -> SqliSandbox:
    temp = TemporaryDirectory(prefix="arsenal-sqli-")
    root = Path(temp.name)
    conn = sqlite3.connect(root / "sqli.db")
    outside = root / "outside"
    outside.mkdir()
    conn.executescript(
        """
        CREATE TABLE users (name TEXT PRIMARY KEY, pass TEXT, role TEXT);
        CREATE TABLE tokens (owner TEXT, token TEXT);
        CREATE TABLE notes (name TEXT, note TEXT);
        INSERT INTO users VALUES ('admin', 'ARSENAL-DB-SECRET', 'ZZZ-ADMIN');
        INSERT INTO users VALUES ('alice', 'alicepass', 'MMM-USER');
        INSERT INTO users VALUES ('guest', 'guestpass', 'AAA-USER');
        INSERT INTO tokens VALUES ('admin', 'ARSENAL-TOKEN-ADMIN');
        INSERT INTO tokens VALUES ('guest', 'ARSENAL-TOKEN-GUEST');
        INSERT INTO notes VALUES ('admin', 'reset phrase: ARSENAL-DB-SECRET');
        INSERT INTO notes VALUES ('guest', 'welcome guest note');
        """
    )
    payloads = {
        "sqli_classic_tautology": {"u": "' OR 1=1--", "p": "irrelevant"},
        "sqli_comment_auth_bypass": {"u": "admin'--", "p": "irrelevant"},
        "sqli_decode_after_filter": {
            "u": "%27 OR name=%27admin%27--",
            "p": "irrelevant",
        },
        "sqli_nfkc_fullwidth_quote": {
            "u": "＇ OR name=＇admin＇--",
            "p": "irrelevant",
        },
        "sqli_second_order_stored": {"name": "x' OR '1'='1'--"},
        "sqli_like_wildcard_disclosure": {"term": "%"},
        "sqli_order_by_case_blind": {
            "sort": (
                "(CASE WHEN (SELECT substr(pass,1,1) FROM users "
                "WHERE name='admin')='A' THEN name ELSE role END)"
            )
        },
        "sqli_pragma_recon": {"script": "PRAGMA journal_mode = WAL"},
        "sqli_attach_file_write": {
            "script": (
                f"ATTACH DATABASE '{(outside / 'arsenal_pwned.db').as_posix()}'"
                " AS x; CREATE TABLE x.pwned(marker TEXT);"
                f" INSERT INTO x.pwned VALUES('{ATTACH_MARKER}')"
            )
        },
        "sqli_hex_blob_smuggle": {"expr": "CAST(x'61646d696e' AS TEXT)"},
        "sqli_char_runtime_string": {"expr": "char(97,100,109,105,110)"},
        "sqli_cte_exfil": {
            "expr": (
                "(WITH s AS (SELECT pass FROM users "
                "WHERE name=char(97,100,109,105,110)) SELECT pass FROM s)"
            )
        },
        "sqli_inline_comment_split": {
            "u": "x'/**/OR/**/name='admin'--",
            "p": "irrelevant",
        },
        "sqli_boolean_blind_substr": {
            "term": (
                "x' OR (SELECT substr(note,1,1) FROM notes WHERE name='admin') LIKE 'r"
            )
        },
    }
    return SqliSandbox(
        conn=conn,
        outside_db=outside / "arsenal_pwned.db",
        payloads=payloads,
        _temp=temp,
    )


# --------------------------------------------------------------------------
# Наивная реализация
# --------------------------------------------------------------------------


def naive_login(ctx: SqliSandbox, u: str, p: str) -> tuple | None:
    if "'" in u or "'" in p:  # фильтр кавычек
        raise NaiveRejected("quote_filter")
    u = unicodedata.normalize("NFKC", u)  # «поддержка юникод-имён»
    p = unicodedata.normalize("NFKC", p)
    u = unquote(u)  # ручная обработка percent-encoding — ПОСЛЕ фильтра
    p = unquote(p)
    sql = f"SELECT name, role FROM users WHERE name='{u}' AND pass='{p}'"
    return ctx.conn.execute(sql).fetchone()


def naive_legacy_login(ctx: SqliSandbox, u: str, p: str) -> tuple | None:
    sql = f"SELECT name, role FROM users WHERE name='{u}' AND pass='{p}'"
    return ctx.conn.execute(sql).fetchone()


def naive_register(ctx: SqliSandbox, name: str) -> None:
    # вставка параметризована — регистрация сама по себе безопасна
    ctx.conn.execute("INSERT OR REPLACE INTO users VALUES (?, 'x', 'USER')", (name,))


def naive_profile(ctx: SqliSandbox, name: str) -> list[tuple] | None:
    row = ctx.conn.execute(
        "SELECT name, role FROM users WHERE name = ?", (name,)
    ).fetchone()
    if row is None:
        return None
    stored = row[0]
    # «значение из своей БД — доверенное»: встраивается в SQL как есть
    sql = f"SELECT token FROM tokens WHERE owner='{stored}'"
    return ctx.conn.execute(sql).fetchall()


def naive_search(ctx: SqliSandbox, term: str) -> list[tuple]:
    sql = f"SELECT name, note FROM notes WHERE note LIKE '%{term}%'"
    return ctx.conn.execute(sql).fetchall()


def naive_list_users(ctx: SqliSandbox, sort: str) -> list[tuple]:
    sql = f"SELECT name, role FROM users ORDER BY {sort}"
    return ctx.conn.execute(sql).fetchall()


def naive_admin_tool(ctx: SqliSandbox, script: str) -> None:
    ctx.conn.executescript(script)


def naive_user_lookup(ctx: SqliSandbox, expr: str) -> tuple | None:
    # «рекон»-эндпоинт: выражение уходит и в WHERE, и в колонку результата
    sql = f"SELECT name, role, {expr} FROM users LIMIT 1"
    return ctx.conn.execute(sql).fetchone()


def naive_run(ctx: SqliSandbox, vector_id: str) -> tuple[bool, str]:
    payload = ctx.payloads[vector_id]
    if vector_id in {
        "sqli_classic_tautology",
        "sqli_comment_auth_bypass",
        "sqli_inline_comment_split",
    }:
        row = naive_legacy_login(ctx, payload["u"], payload["p"])
        ok = row is not None and row[0] == ADMIN_NAME
        return ok, f"вход как {row[0]}" if ok else "вход не удался"
    if vector_id in {"sqli_decode_after_filter", "sqli_nfkc_fullwidth_quote"}:
        row = naive_login(ctx, payload["u"], payload["p"])
        ok = row is not None and row[0] == ADMIN_NAME
        return ok, f"вход как {row[0]}" if ok else "вход не удался"
    if vector_id == "sqli_second_order_stored":
        naive_register(ctx, payload["name"])
        rows = naive_profile(ctx, payload["name"])
        tokens = {r[0] for r in rows or []}
        ok = ADMIN_TOKEN in tokens and len(tokens) >= 2
        return ok, f"утечка токенов: {len(tokens or [])} строк" if ok else "утечки нет"
    if vector_id == "sqli_like_wildcard_disclosure":
        rows = naive_search(ctx, payload["term"])
        leaked = any(NOTE_SECRET in r[1] for r in rows)
        return leaked, f"получено заметок: {len(rows)}" if leaked else "утечки нет"
    if vector_id == "sqli_order_by_case_blind":
        order_yes = naive_list_users(ctx, payload["sort"])
        order_no = naive_list_users(ctx, payload["sort"].replace("='A'", "='Z'"))
        ok = [r[0] for r in order_yes] != [r[0] for r in order_no]
        return ok, "порядок выдаёт символ пароля" if ok else "оракул молчит"
    if vector_id == "sqli_pragma_recon":
        naive_admin_tool(ctx, payload["script"])
        mode = ctx.conn.execute("PRAGMA journal_mode").fetchone()[0]
        return mode.lower() == "wal", f"журнал переключён: {mode}"
    if vector_id == "sqli_attach_file_write":
        naive_admin_tool(ctx, payload["script"])
        ok = ctx.outside_db.is_file()
        return ok, "файл создан за пределами БД" if ok else "файла нет"
    if vector_id in {"sqli_hex_blob_smuggle", "sqli_char_runtime_string"}:
        row = naive_user_lookup(ctx, payload["expr"])
        ok = row is not None and row[0] == ADMIN_NAME
        return ok, f"подобран пользователь {row[0]}" if ok else "подбор не удался"
    if vector_id == "sqli_cte_exfil":
        row = naive_user_lookup(ctx, payload["expr"])
        ok = row is not None and NOTE_SECRET in str(row)
        return ok, "пароль администратора в выдаче" if ok else "секрета нет"
    if vector_id == "sqli_boolean_blind_substr":
        rows_yes = naive_search(ctx, payload["term"])
        rows_no = naive_search(ctx, payload["term"].replace("LIKE 'r", "LIKE 'Z"))
        ok = len(rows_yes) > 0 and len(rows_no) == 0
        return ok, "оракул отвечает посимвольно" if ok else "оракул не работает"
    return False, "неизвестный вектор"


# --------------------------------------------------------------------------
# Охраняемая реализация
# --------------------------------------------------------------------------


def safe_sql_text(value: str) -> str:
    """Q4: канонизация входа и запрет quote-класса и кодовых конструкций."""
    v = fully_decode(str(value))
    v = unicodedata.normalize("NFKC", v)
    if any(ord(ch) < 32 for ch in v):
        raise DefenseHold("Q4", "control_char")
    if any(c in v for c in _SQL_QUOTE_CLASS) or "--" in v or "/*" in v:
        raise DefenseHold("Q4", "quote_or_comment_class")
    for pattern in _SQL_LITERAL_PATTERNS:
        if pattern.search(v):
            raise DefenseHold("Q4", "encoded_literal_construction")
    return v


def guarded_login(ctx: SqliSandbox, u: str, p: str) -> tuple | None:
    u = safe_sql_text(u)
    p = safe_sql_text(p)
    return ctx.conn.execute(
        "SELECT name, role FROM users WHERE name = ? AND pass = ?", (u, p)
    ).fetchone()


def _like_escape_mask(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def guarded_search(ctx: SqliSandbox, term: str) -> list[tuple]:
    pattern = _like_escape_mask(safe_sql_text(term))  # Q5: маскирование
    return ctx.conn.execute(
        "SELECT name, note FROM notes WHERE note LIKE ? ESCAPE '\\'",
        (f"%{pattern}%",),
    ).fetchall()


def guarded_list_users(ctx: SqliSandbox, sort: str) -> list[tuple]:
    column = SORT_COLUMNS.get(sort)  # Q2: allowlist идентификаторов
    if column is None:
        raise DefenseHold("Q2", "sort_column_not_allowed")
    return ctx.conn.execute(
        f"SELECT name, role FROM users ORDER BY {column}"  # noqa: S608 - allowlist
    ).fetchall()


def guarded_admin(ctx: SqliSandbox, operation: str) -> str:
    if operation not in SQLI_OPS_ALLOWED:  # Q3: фиксированный реестр
        raise DefenseHold("Q3", "admin_operation_not_allowed")
    if operation == "journal_mode":
        return str(ctx.conn.execute("PRAGMA journal_mode").fetchone()[0])
    ctx.conn.execute("VACUUM")
    return "vacuum done"


def guarded_register(ctx: SqliSandbox, name: str) -> None:
    ctx.conn.execute(
        "INSERT OR REPLACE INTO users VALUES (?, 'x', 'USER')", (safe_sql_text(name),)
    )


def guarded_profile(ctx: SqliSandbox, name: str) -> list[tuple] | None:
    row = ctx.conn.execute(
        "SELECT name, role FROM users WHERE name = ?", (safe_sql_text(name),)
    ).fetchone()
    if row is None:
        return None
    stored = safe_sql_text(row[0])  # Q6: повторная проверка значения из БД
    return ctx.conn.execute(
        "SELECT token FROM tokens WHERE owner = ?", (stored,)
    ).fetchall()


def guarded_run(ctx: SqliSandbox, vector_id: str) -> tuple[bool, str, str]:
    payload = ctx.payloads[vector_id]
    try:
        if vector_id in {
            "sqli_classic_tautology",
            "sqli_comment_auth_bypass",
            "sqli_inline_comment_split",
        }:
            # Q1: legacy-эндпоинт удалён; единственный вход — параметризованный
            row = guarded_login(ctx, payload["u"], payload["p"])
            if row is not None and row[0] == ADMIN_NAME:
                return False, "", "охраняемый логин пропустил обход"
            return True, "Q1", "вход не выполнен: параметризация + канонизация"
        if vector_id in {"sqli_decode_after_filter", "sqli_nfkc_fullwidth_quote"}:
            guarded_login(ctx, payload["u"], payload["p"])
            return True, "Q4", "канонизация раскрыла и отвергла payload"
        if vector_id == "sqli_second_order_stored":
            guarded_register(ctx, payload["name"])
            guarded_profile(ctx, payload["name"])
            return True, "Q6", "значение из БД перепроверено"
        if vector_id in {"sqli_like_wildcard_disclosure", "sqli_boolean_blind_substr"}:
            guarded_search(ctx, payload["term"])
            return True, "Q5", "wildcards замаскированы ESCAPE"
        if vector_id == "sqli_order_by_case_blind":
            guarded_list_users(ctx, payload["sort"])
            return True, "Q2", "сортировка только по allowlist"
        if vector_id in {"sqli_pragma_recon", "sqli_attach_file_write"}:
            guarded_admin(ctx, payload["script"])
            return True, "Q3", "операция вне фиксированного реестра"
        if vector_id in {
            "sqli_hex_blob_smuggle",
            "sqli_char_runtime_string",
            "sqli_cte_exfil",
        }:
            # Q1: эндпоинт сырых выражений удалён; что осталось — отвергает Q4
            safe_sql_text(payload["expr"])
            return True, "Q1", "эндпоинт сырых выражений удалён"
    except DefenseHold as hold:
        return True, hold.layer, hold.code
    return False, "", "охраняемая реализация допустила инъекцию"


# --------------------------------------------------------------------------
# Кампании и матрица
# --------------------------------------------------------------------------


def campaign() -> CampaignResult:
    result = CampaignResult(category="sqli", title="SQLI: инъекции в SQLite")
    with build_context() as ctx:
        for vector in VECTORS:
            if vector.id in ctx.unavailable():
                result.outcomes.append(
                    VectorOutcome(vector, None, "пропуск платформой", None, "", "")
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
