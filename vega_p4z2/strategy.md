# P4Z2: Отчёт, которому не верят

## Цель
Форма входа на `http://target:8000` подставляет логин в SQL-запрос как есть → войти в кабинет без пароля через SQL-инъекцию, забрать флаг, записать его точное значение в `$VEGA_CTF_ARTIFACT_DIR/flag.txt`. Checker обрезает пробелы и сравнивает посимвольно. Лимиты: 600 с, 512 МиБ. Исходники службы — в `$VEGA_TASK_DIR/materials`.

## Легенда → векторы (SQLi login bypass)

| # | Вектор | Payload |
|---|--------|---------|
| 1 | Классический OR-bypass | `' OR 1=1 -- ` / `' OR '1'='1` / `') OR ('1'='1` |
| 2 | Комментарий хвоста запроса | `admin'--` / `admin' #` / `admin'-- -` |
| 3 | Обход фильтра пробелов/слов | `'/**/OR/**/1=1--` / tab вместо пробела / `admin'--` (без OR вовсе) |
| 4 | Другая кавычка / GET-форма | `" OR 1=1 -- ` / `/login?username=admin'--&password=x` |
| 5 | Сессия после входа | 302 + Set-Cookie → флаг на /dashboard или по ссылке (вплоть до two-hop) |

## Архитектура — наследие победителей + SQLi-домен

Тот же LLM-цикл с инструментами (54 шага, окно 18 сообщений, дедлайн 580 с), что выиграл P2Z1/P2Z3/P2Z4/P2Z5/P3Z2/P3Z3:

- **материалы-инструменты**: `inventory`, `read_file`, `grep_files` (поиск SELECT/password/execute в исходниках), `decode`.
- **http**: GET с авто-прикреплением cookie сессии; `http_batch` — до 60 параллельно.
- **http_post** (новое): POST-форма без auto-follow — захватывает статус, Set-Cookie, Location и тело; cookie сохраняется глобально и прикрепляется ко всем последующим запросам.
- **login_probe** (главный инструмент):
  1. **поиск формы**: GET /, /login, /admin, /signin, /auth... → парсинг `<form action= method= >` и имён `<input>` (защита от CSRF-полей), выбор пары login_field/password_field по ключевым словам;
  2. **baseline**: POST с заведомо неверными кредами → sha1/cookie/location для детекции успеха;
  3. **матрица payload'ов**: 30 username × 2-3 password (Phase 1 — классика с password=x; Phase 2 — инъекция в password; Phase 3 — GET-вариант того же endpoint'а);
  4. **детекция успеха**: flag_shaped ИЛИ (тело ≠ baseline) И (маркер welcome/dashboard/flag ИЛИ set-cookie ИЛИ location), с отсечением «Неверный логин»;
  5. **следование сессии**: GET location + dashboard-пути с cookie; парсинг `href` с аутентифицированных страниц и догрузка интересных ссылок (двухшаговый сценарий /dashboard → /admin/flag).
- **finish-валидация**: флаг принимается только если он реально встречался в живых ответах (`EVIDENCE["http"]`); graceful fallback — последний flag-shaped из evidence.

## Ключевые решения

- **Захват cookie без редиректа**: `http_post` не следует за 302 — Location и Set-Cookie возвращаются агенту как данные, потом `http_get` с сохранённой сессией идёт по кабинетам. Так флаг на /dashboard всегда виден.
- **Детекция успеха по sha1**: любое отличие тела от baseline плюс маркер/cookie/redirect — успех; «Неверный логин или пароль» отсекается маркер-фильтром (invalid|wrong|ошибк...).
- **Парсинг формы**: agent узнаёт точные имена полей и action из HTML — не полагается на догадки username/password.
- **Реальные SQL-семантики в тестах**: mock использует настоящий sqlite3 с уязвимым string-concat запросом, так что инъекции работают аутентично (комментарии, кавычки, OR — всё по-настоящему).

## Проверка (все 5 сценариев на агенте)
- **m1**: POST /login, флаг в ответе на `' OR 1=1 -- ` — PASS.
- **m2**: POST /login → 302 + cookie → флаг на /dashboard — PASS.
- **m3**: фильтр ввода (пробелы и слово OR запрещены) → `admin'--` — PASS.
- **m4**: GET-форма `/login?username=admin'--&password=x` — PASS.
- **m5**: cookie → /dashboard → ссылка /admin/flag (двухшаговое следование) — PASS.

Инфраструктура: `scripts/mock_server_p4z2.py` (5 режимов, sqlite3), `scripts/mock_model_p4z2.py` (детерминированная модель), `scripts/test_p4z2.sh` (E2E, очистка портов fuser+pgrep).
