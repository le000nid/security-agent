# Проверки NoSQLi

Новый блок с настоящей MongoDB: [запуск и сценарии](MONGO_LAB.md).
Краткая [карта файлов](FILE_MAP.md). Ниже — предыдущая проверка Juice Shop.

Добавлены две части:
- DAST: проверка изменения выборки отзывов в Juice Shop через Nuclei.
- SAST: правило Semgrep для пользовательского ввода в `$where`.

SAST проверяет отдельные учебные JS-файлы, а не весь исходный код
Juice Shop. Поэтому в агенте это два разных набора проверок.

## Где что лежит

- `config/nuclei/juice-shop-nosqli-reviews.yaml` — DAST-шаблон.
- `config/semgrep.yaml` — правило `javascript-nosqli-tainted-where`.
- `targets/nosqli/vulnerable.js` — два уязвимых примера.
- `targets/nosqli/safe.js` — два безопасных контрольных примера.
- `config/benchmarks.yaml` — записи `nosqli-sast` и `nosqli-dast`.
- `docker-compose.nosqli.yml` — отдельный учебный Juice Shop.

## Как работает проверка

В уязвимом обработчике номер товара попадает в текст условия `$where`.
Если вместо номера передать выражение, оно может изменить выборку.

Nuclei сравнивает три ответа:
1. Обычный запрос возвращает отзывы товара 1.
2. Истинное условие возвращает также отзывы других товаров.
3. Ложное условие возвращает пустой список.

Для находки должны выполниться все условия шаблона.
Точное количество отзывов в проверку не зашито.

Semgrep отслеживает ввод из полей `req.params`, `req.query` и `req.body`
до `$where` в вызовах `find` и `findOne`, включая передачу через переменные.

## Запуск

Нужны Docker и Docker Compose. Команды выполняются в Bash
из корня проекта, в ветке с этими изменениями.

```bash
export AGENT_UID="$(id -u)"
export AGENT_GID="$(id -g)"

mkdir -p runs logs reports
docker compose build agent

docker compose -f docker-compose.yml -f docker-compose.nosqli.yml \
  up -d nosqli-lab
```

В стандартном Docker-запуске Juice Shop v20.2.0 эта учебная
уязвимость отключена. Отдельный стенд использует
`challenges.safetyMode=disabled`. Это включает и другие ограниченные
учебные задания. Порт доступен только на локальном компьютере.

Проверить готовность сайта:

```bash
curl --fail --max-time 10 -sS \
  http://localhost:3004/rest/products/1/reviews
```

Если сайт ещё запускается, повторить команду после его запуска.
Ожидается JSON со статусом `success` и отзывами.

### SAST

```bash
docker compose --profile agent run --rm --no-deps \
  agent scan --benchmark nosqli-sast --mode sast --no-llm
```

Ожидаются две находки `javascript-nosqli-tainted-where`
в `vulnerable.js`. В `safe.js` находок быть не должно.

### DAST

```bash
docker compose -f docker-compose.yml -f docker-compose.nosqli.yml \
  --profile agent run --rm --no-deps \
  agent scan --benchmark nosqli-dast --mode dast --no-llm
```

Запускается весь набор Nuclei-шаблонов. Среди результатов должна быть:
`Juice Shop reviews NoSQL query manipulation`.

Путь к отчётам агент выводит в терминал:
- `runs/<ID>/reports/report.md`
- `runs/<ID>/reports/findings.json`
- `runs/<ID>/reports/summary.json`

Адрес находки может содержать последний, ложный запрос.
Срабатывание основано на сравнении всех трёх ответов.

### Контроль на стандартном Juice Shop

```bash
docker compose up -d juice-shop

docker compose --profile agent run --rm --no-deps \
  -e HOME=/tmp --entrypoint nuclei agent \
  -u http://juice-shop:3000 \
  -t /agent/config/nuclei/juice-shop-nosqli-reviews.yaml \
  -disable-update-check -no-interactsh
```

После готовности стандартного стенда ожидается `No results found`.
Это проверка отсутствия срабатывания на варианте с отключённым
уязвимым механизмом, а не доказательство безопасности всего приложения.

## Что проверено вручную

- Учебный стенд: обычный запрос — 2 отзыва, истинное условие — 29,
  ложное — 0. Числа зависят от данных стенда.
- Nuclei: одна находка на уязвимом экземпляре, ноль на стандартном.
- Semgrep: две находки в уязвимом файле, ноль в безопасном.
- Общий агент: SAST дал две находки; DAST дал пять,
  включая нашу NoSQLi. Результаты попали в Markdown и JSON.

## Ограничения

DAST-шаблон рассчитан на маршрут отзывов Juice Shop v20.2.0.
Это не универсальная проверка всех сайтов и всех вариантов NoSQLi.

SAST-правило рассчитано на JavaScript/TypeScript и указанные формы
источников ввода и запросов. Оно не покрывает все обёртки,
межфункциональные потоки и способы проверки входных данных.
Находку в другом проекте нужно проверить вручную.

Внедрение операторов через JSON этим набором не покрыто.
Отдельные HTTP-фикстуры для ответов 500, HTML и одинаковых ответов
пока не добавлены.

## После изменения правил

Пересобрать образ:

```bash
docker compose build agent
```

Установленный агент использует упакованные ресурсы:
одного подключения `/agent/config` оказалось недостаточно
для обновления правил при нашем запуске.

## Остановка учебного стенда

```bash
docker compose -f docker-compose.yml -f docker-compose.nosqli.yml \
  stop nosqli-lab
```
