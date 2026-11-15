# P3Z3: Доверяй, но пересчитывай

## Цель
Обойти проверку пути, которая смотрит на «хвост» ДО того, как путь собран целиком. Замок запирает не ту дверь: фильтр видит одно значение, сервер собирает/читает другое. Добраться до закрытого файла и записать его точное содержимое в `$VEGA_CTF_ARTIFACT_DIR/flag.txt`. Checker обрезает пробелы и сравнивает посимвольно. Лимиты: 600 с, 512 МиБ.

## Легенда → векторы (5 классов check-before-assembly)

| # | Вектор | Что видит фильтр | Что читает сервер |
|---|--------|-----------------|-------------------|
| 1 | **HPP** — `?file=safe.txt&file=../secret.txt` | `safe.txt` (первый) | `../secret.txt` (последний) |
| 2 | **multi-param** — `?name=safe.txt&path=../secret.txt` | `name=safe.txt` (canonical) | `path=../secret.txt` |
| 3 | **suffix-concat** — `?file=../secret` (сервер добавляет `.txt`) | `../secret` (но фильтр имени) | `../secret.txt` (после сборки) |
| 4 | **double-decode** — `?file=%252e%252e%252fsecret.txt` | `%2e%2e%2fsecret.txt` (один decode) | `../secret.txt` (второй decode) |
| 5 | **abs-path + HPP** — `?file=safe.txt&file=/etc/passwd` | `safe.txt` | `/etc/passwd` (os.path.join discard base) |

Все 5 — это разные формы одной ошибки: проверка идёт до нормализации/сборки пути.

## Архитектура — наследие P3Z2 + усиление

Та же проверенная архитектура LLM-цикла с инструментами (54 шага, окно 18 сообщений, дедлайн 580 с):
- **инструменты**: `inventory`, `read_file`, `grep_files`, `http`, `http_batch`, `http_discover`, `http_traverse`, `unpack_url`, `decode`, `finish`.
- **http_discover**: two-pass проба endpoints × params с публичным seed; маршрут = параметризованный 200 с телом ≠ главной (sha1).
- **http_traverse** — усилен новыми фазами для P3Z3:
  - **Phase A**: абсолютные пути `/proc/self/cwd/…`, `/proc/self/root/…` (os.path.join-квирк).
  - **Phase B**: канарейка `/etc/passwd` на каждом маршруте прямыми запросами → подтверждённый bypass-префикс.
  - **Phase B2 (новое для P3Z3)**: HPP-матрица — `?file=safe&file=target`, `?file=safe&file=../target`, multi-param `?name=safe&path=target`, suffix-concat `target.bak`, abs-path HPP `?file=safe&file=/etc/passwd`. Все генерируются автоматически с публичным safe_pub и канарейкой.
  - **Phase B3 (новое для P3Z3)**: double-decode матрица — `%252e%252e%252f`, `..%252f`, `%252e%252e%252f%252e%252e%252f`. Отдельная фаза (до классической матрицы), чтобы глубокие sweeps с множеством имён не вытеснили эти векторы за лимит 360 запросов.
  - **Phase C**: классическая матрица bypass×глубина×имя (PATH_BYP: 21 вариант × depth 1-6) — наследие P3Z2.
  - **Phase D**: альтернативные маршруты + префиксы каталогов.
- **finish-валидация**: флаг принимается ТОЛЬКО если он в сохранённых сырых ответах живого сервиса (`EVIDENCE["http"]`).
- **фолбэки**: последний `last_flag` или лучший flag-shaped из EVIDENCE записываются при любом исходе.

## Ключевое отличие от P3Z2

P3Z2 учил: «фильтр отсекает грубые имена, обходи кодировками». P3Z3 учит: «фильтр проверяет путь ДО сборки — подсунь ему чистый хвост, а сервер собери опасный». Поэтому главная сила теперь не в матрице кодировок, а в **HPP/multi-param/suffix-concat/double-decode** — фазах B2 и B3, которые генерируют запросы с РАЗНЫМИ значениями для фильтра и сервера.

## Проверка (все на пакетированном агенте)
- Детерминированная mock-модель (без реального LLM) — 5 сценариев PASS, каждый покрывает один класс check-before-assembly:
  - **m1 HPP**: `?file=notes.txt&file=../secret.txt` — фильтр видит `notes.txt`, сервер читает последний.
  - **m2 multi-param**: `?name=notes.txt&path=../secret.txt` — фильтр на `name`, сервер на `path`.
  - **m3 suffix-concat**: `?file=notes.txt&file=../secret.txt` — сервер собирает `name + ".txt"` только если нет расширения.
  - **m4 double-decode**: `?file=%252e%252e%252fsecret.txt` — `parse_qs` декодирует один раз (фильтр видит `%2e%2e%2f`), сервер декодирует ещё раз (`../`).
  - **m5 abs-path+HPP**: `?file=notes.txt&file=/etc/passwd` — `os.path.join(base, "/etc/passwd")` отбрасывает base.
- Инфраструктура теста: `scripts/mock_server_p3z3.py` (5 режимов), `scripts/mock_model.py` (детерминированная модель), `scripts/test_p3z3.sh` (E2E с надёжной очисткой портов через `fuser` + `pgrep`).
