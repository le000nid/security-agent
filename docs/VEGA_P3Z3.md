# VEGA P3Z3 agent («Доверяй, но пересчитывай»)

`vega_p3z3/` — третий автономный экспорт для тестовой системы VEGA: агент
поколения P3Z3 обходит проверку пути, которая смотрит на пользовательское
значение ДО того, как финальный путь собран целиком (классический
check-before-use), и доставляет закрытый секрет в
`$VEGA_CTF_ARTIFACT_DIR/flag.txt`. Как и базовый [VEGA adapter](VEGA.md) и
[VEGA P3Z2 agent](VEGA_P3Z2.md), он не меняет SAST/DAST pipeline, benchmark
или правила основного приложения и поставляется отдельным архивом без
зависимостей (только стандартная библиотека Python).

Все три экспорта собираются одной командой:

```powershell
python scripts/build_vega.py
```

Результат: `dist/security-agent-vega.zip`, `dist/security-agent-p3z2.zip` и
`dist/security-agent-p3z3.zip`. В корне каждого архива находятся ровно
`run.sh`, `agent.json`, `agent.py`, `strategy.md`.

## Архитектура

Та же архитектура, что принесла победы P2Z1/P2Z3/P2Z4/P2Z5/P3Z2: компактный
LLM-цикл с инструментами (54 шага, окно 18 сообщений, дедлайн 580 секунд),
где модель расследует, инструменты исполняют, а `finish` валидируется по
живым HTTP-ответам (`EVIDENCE["http"]`).

```text
instruction.md + materials -> LLM -> одно JSON-действие -> инструмент
        -> наблюдение -> LLM ... -> finish -> проверка по EVIDENCE -> flag.txt
```

## Ключевое отличие от P3Z2

P3Z2 учил: «фильтр отсекает грубые имена — обходи кодировками». P3Z3 учит:
«фильтр проверяет путь до сборки — подсунь ему чистый хвост, а сервер собери
опасный». Пять классов check-before-assembly:

| # | Вектор | Что видит фильтр | Что читает сервер |
|---|--------|-----------------|-------------------|
| 1 | HPP — `?file=safe.txt&file=../secret.txt` | `safe.txt` (первый) | `../secret.txt` (последний) |
| 2 | multi-param — `?name=safe.txt&path=../secret.txt` | `name=safe.txt` | `path=../secret.txt` |
| 3 | suffix-concat — `?file=../secret` (сервер добавляет `.txt`) | `../secret` | `../secret.txt` |
| 4 | double-decode — `?file=%252e%252e%252fsecret.txt` | `%2e%2e%2fsecret.txt` | `../secret.txt` |
| 5 | abs-path + HPP — `?file=safe.txt&file=/etc/passwd` | `safe.txt` | `/etc/passwd` (join отбрасывает base) |

## Инструменты

Набор тот же, что у P3Z2 (`inventory`, `read_file`, `grep_files`, `http`,
`http_batch`, `http_discover`, `http_traverse`, `unpack_url`, `decode`,
`finish`), но `http_traverse` усилен двумя фазами:

- **Phase B2 (новое)** — HPP-матрица: `?file=safe&file=target`, HPP с
  traversal на 1..max_depth уровней, обращённый порядок значений,
  abs-target через HPP, multi-param по 8 альтернативным именам параметра
  (в обоих порядках, с abs-целью и traversal на 1..2), suffix-concat
  (`.bak/.old/.txt/.log/~/swp`), плюс канарейки `/etc/passwd` через HPP-abs
  и multi-param-abs. Имя параметра извлекается из raw query маршрута.
- **Phase B3 (новое)** — double-decode матрица (5 вариантов `%252e…`,
  прямые и HPP-encoded формы). Выполняется ДО классической матрицы, чтобы
  глубокие sweeps с множеством имён не вытеснили эти векторы за лимит 360
  запросов; при первом flag-shaped хите фаза возвращает результат досрочно.

Досрочные возвраты: `double_decode_hits` (подсказка «DOUBLE-DECODE BYPASS
CONFIRMED») и `hpp_multi_param_hits` (подсказка «check-before-assembly BYPASS
CONFIRMED via HPP/multi-param»). Классические фазы P3Z2 (канарейка `/etc/passwd`,
матрица bypass×глубина×имя из 22 обходов, `/proc/self/…`, альтернативные
маршруты и префиксы каталогов) сохранены и выполняются, если новые фазы не
дали flag-shaped результата; их хиты объединяются в общий `matrix_hits` и
сводку `FLAG_SHAPED`.

## Границы безопасности

Идентичны P3Z2 и усилены теми же тремя правками интеграции:

- файловые операции остаются внутри canonical `MATERIALS` (`VEGA_TASK_DIR`);
  guard использует `realpath` и строгий префикс — symlink- и
  sibling-directory escape отклоняются;
- HTTP ограничен `VEGA_TARGET_URL` (по умолчанию `http://target:8000`),
  redirects только внутри того же scheme/host/port; GET/HEAD; пути с
  control-символами и длиннее 1400 отклоняются;
- цикл ограничен `VEGA_AGENT_MAX_STEPS` (54) и дедлайном 580 секунд;
- stderr не содержит содержимого реплик и значений флага;
- артефакт пишется атомарно и содержит только значение флага;
- недостающая конфигурация LLM даёт одну безопасную ошибку без секретов.

## Отличия от исходного P3Z3-агента

Код логики перенесён 1:1 (проверено AST-сравнением с исходным файлом) и
приведён к стандартам проекта: Ruff-форматирование, сортировка импортов и
те же три харденинг-правки, что и для P3Z2 (path-guard на realpath + строгий
префикс, атомарная запись артефакта, безопасная ошибка конфигурации LLM),
плюс расширение v2 (см. ниже).

## Расширение v2 — универсализация

Поверх фаз A/B/B2/B3/C/D движок усилен пятью механизмами (каждый покрыт
офлайн-тестом, дисциплина бюджета запросов сохранена; список идентичен
[VEGA_P3Z2.md](VEGA_P3Z2.md)):

- **PATH_BYP 22 → 28 векторов**: backslash/mixed-slash (`..\`, `..\/`),
  encoded-dot формы (`%2e%2e/`, `%2e%2e%5c`), overlong UTF-8
  (`..%e0%80%af`), unicode solidus (`..%u2215`).
- **Phase A2**: 18 фиксированных абсолютных чтений независимо от угаданных
  имён — `/proc/self/environ`, `/proc/self/cmdline`, `/etc/environment`,
  `/proc/self/cwd/app.py|main.py|server.py|wsgi.py|.env|.htaccess` и другие
  источники и метаданные службы.
- **Варианты имён 3 → 6**: dotfile (`.flag`), hex-dotfile (`.f%6cag.txt`
  против RAW-фильтров), имя без расширения (`flag.txt` → `flag` — сервер
  сам дописывает расширение при сборке; родственный suffix-concat вектор).
- **base64-автодекод флагов** в `http_get` (блобы ≥24 символов); найденный
  секрет попадает в `flag_shaped_values` и EVIDENCE.
- **http_discover round 3/4**: href/src/action-ссылки главной и plain-пути
  (`/files/notes.txt`); результаты — `href_routes` и `plain_path_hits`.

## Проверка

Offline-проверки не используют сеть: уязвимый сервис реализован в памяти с
семантикой check-before-assembly (фильтр видит только первое значение
`file`; сервер читает последнее значение / `path`-параметр, вторично
декодирует и дописывает расширение), модель скриптуется.

```powershell
pytest -q tests/test_vega_p3z3.py
```

22 теста: контракт архива, path-guard (escape/sibling/symlink), контракты
путей и разбора реплик, `unwrap_body`, flag-shaped regex, redirect-guard,
безопасная ошибка конфигурации, evidence/кэш, поведение фильтра на грубые
имена, `http_batch`, `decode`, три сквозных сценария:

- e2e «double-decode wins»: секрет на уровень выше `public/`; сервис
  вторично декодирует; фаза B3 возвращает `DOUBLE-DECODE BYPASS CONFIRMED`;
- e2e «HPP wins»: секрет в `secret/`; без вторичного декодирования; фаза B2
  возвращает `check-before-assembly BYPASS CONFIRMED via HPP/multi-param`;
- e2e отказ выдуманному флагу с последующим подтверждённым завершением;

и шесть тестов расширения v2: расширенный PATH_BYP, base64-автодекод (юнит и
через `http_get`), Phase A2 (секрет в `/proc/self/environ` находится без
угадывания имён), dotfile-hex вариант имени против RAW-фильтра (через
классическую матрицу, без досрочного возврата B2/B3) и разведка
href/plain-путей в `http_discover`.

Сценарии m1–m5 из `strategy.md` выполнены на исходном пакетированном агенте
до интеграции (детерминированная mock-модель); интегрированный агент
отличается тремя харденинг-правками и расширением v2, покрытыми
офлайн-тестами.

> Минимальный `agent.json` (`format: vega-agent-harness`) следует подтвердить
> реальным VEGA validator до публикации архива для конкретной инсталляции.
