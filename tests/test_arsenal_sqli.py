"""Арсенал SQLI: каждый вектор реально эксплуатирует SQLite и остановлен слоями."""

from __future__ import annotations

import pytest

from app.agent.arsenal import sqli
from app.agent.arsenal.core import DefenseHold


@pytest.fixture()
def sandbox():
    with sqli.build_context() as ctx:
        yield ctx


@pytest.mark.parametrize("vector", sqli.VECTORS, ids=lambda v: v.id)
def test_vector_unguarded_and_guarded(sandbox, vector):
    attack_ok, attack_detail = sqli.naive_run(sandbox, vector.id)
    assert attack_ok, f"наивная реализация устояла: {attack_detail}"
    hold_ok, hold_layer, hold_detail = sqli.guarded_run(sandbox, vector.id)
    assert hold_ok, f"охраняемая реализация пропустила: {hold_detail}"
    assert hold_layer in vector.stopped_by


def test_naive_login_filter_stops_only_plain_quotes(sandbox):
    with pytest.raises(sqli.NaiveRejected):
        sqli.naive_login(sandbox, "admin'--", "x")
    # полноширинная кавычка проходит фильтр и NFKC превращает её в '
    row = sqli.naive_login(sandbox, "＇ OR name=＇admin＇--", "x")
    assert row is not None and row[0] == sqli.ADMIN_NAME


def test_placeholders_neutralize_quotes(sandbox):
    # Q4 отвергает payload до запроса; плейсхолдеры держат значение строкой
    with pytest.raises(DefenseHold) as hold:
        sqli.guarded_login(sandbox, "admin'--", "anything")
    assert hold.value.layer == "Q4"
    # значение без quote-класса проходит и не ломает структуру запроса
    row = sqli.guarded_login(sandbox, "admin", "wrong-password")
    assert row is None


def test_like_escape_mask_neutralizes_wildcards(sandbox):
    rows = sqli.guarded_search(sandbox, "%")
    assert rows == []  # % больше не метасимвол, литерального '%' в заметках нет


def test_sort_allowlist_rejects_expressions(sandbox):
    with pytest.raises(DefenseHold) as hold:
        sqli.guarded_list_users(sandbox, "(CASE WHEN 1=1 THEN name ELSE role END)")
    assert hold.value.layer == "Q2"


def test_admin_registry_rejects_pragma_and_attach(sandbox):
    with pytest.raises(DefenseHold) as pragma:
        sqli.guarded_admin(sandbox, "PRAGMA journal_mode = WAL")
    assert pragma.value.layer == "Q3"
    with pytest.raises(DefenseHold) as attach:
        sqli.guarded_admin(sandbox, f"ATTACH DATABASE '{sandbox.outside_db}' AS x")
    assert attach.value.layer == "Q3"


def test_second_order_recheck_holds_stored_payload(sandbox):
    # raw-имено попадает в БД через наивную ветку (параметризованная вставка)
    sqli.naive_register(sandbox, "x' OR '1'='1--")
    # охраняемый профильный путь отвергает payload на входе и при перепроверке
    with pytest.raises(DefenseHold) as hold:
        sqli.guarded_profile(sandbox, "x' OR '1'='1--")
    assert hold.value.layer in {"Q4", "Q6"}


def test_blob_and_char_constructions_rejected(sandbox):
    with pytest.raises(DefenseHold) as blob:
        sqli.safe_sql_text("CAST(x'61646d696e' AS TEXT)")
    assert blob.value.layer == "Q4"
    with pytest.raises(DefenseHold) as char_fn:
        sqli.safe_sql_text("char(97,100,109,105,110)")
    assert char_fn.value.layer == "Q4"


# --------------------------------------------------------------------------
# v10: комплексные векторы и простой залп — явные проверки новых слоёв
# --------------------------------------------------------------------------


def test_union_and_group_concat_hold_at_q4(sandbox):
    for vector_id in ("sqli_union_select_exfil", "sqli_group_concat_dump"):
        with pytest.raises(DefenseHold) as hold:
            sqli.guarded_login(sandbox, sandbox.payloads[vector_id]["u"], "irrelevant")
        assert hold.value.layer == "Q4"


def test_naive_union_exfil_returns_tokens(sandbox):
    row = sqli.naive_legacy_login(
        sandbox, sandbox.payloads["sqli_union_select_exfil"]["u"], "irrelevant"
    )
    assert row is not None and sqli.ADMIN_TOKEN in str(row)


def test_vacuum_into_registry_hold(sandbox):
    script = f"VACUUM INTO '{sandbox.exfil_db.as_posix()}'"
    with pytest.raises(DefenseHold) as hold:
        sqli.guarded_admin(sandbox, script)
    assert hold.value.layer == "Q3"


def test_naive_vacuum_into_writes_copy(sandbox):
    script = f"VACUUM INTO '{sandbox.exfil_db.as_posix()}'"
    sqli.naive_admin_tool(sandbox, script)
    assert sandbox.exfil_db.is_file()


def test_system_objects_banned_in_expressions():
    with pytest.raises(DefenseHold) as master:
        sqli.safe_sql_expr("(SELECT name FROM sqlite_master)")
    assert master.value.layer == "Q7"
    with pytest.raises(DefenseHold) as pragma_fn:
        sqli.safe_sql_expr("(SELECT * FROM pragma_table_info('users'))")
    assert pragma_fn.value.layer == "Q4"  # кавычки отвергаются раньше Q7
    with pytest.raises(DefenseHold) as admin_kw:
        sqli.safe_sql_expr("VACUUM")
    assert admin_kw.value.layer == "Q7"


def test_naive_export_keyword_filter_is_case_sensitive(sandbox):
    payload = "x' UNION SeLeCt token, 'x' FROM tokens WHERE owner!='x"
    rows = sqli.naive_export(sandbox, payload)
    assert any(sqli.ADMIN_TOKEN in r[0] for r in rows)
    with pytest.raises(sqli.NaiveRejected):
        sqli.naive_export(sandbox, "x' UNION select token FROM tokens--")


def test_keyword_bypass_holds_at_q4(sandbox):
    payload = sandbox.payloads["sqli_keyword_case_bypass"]["q"]
    with pytest.raises(DefenseHold) as hold:
        sqli.safe_sql_expr(payload)
    assert hold.value.layer == "Q4"


def test_naive_underscore_wildcard_leaks(sandbox):
    rows = sqli.naive_search(sandbox, "_")
    assert any(sqli.NOTE_SECRET in r[1] for r in rows)
    assert sqli.guarded_search(sandbox, "_") == []
