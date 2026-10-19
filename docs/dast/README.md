# DAST: проверки через Nuclei

YAML у нас читается как «Ямаль» ⚽

![Ламин Ямаль](images/lamin-yamal.jpg)

## Что я добавил

Добавил шаблон `config/nuclei/juice-shop-sqlite-error.yaml`.
Он проверяет поиск Juice Shop: отправляет `apple'` и смотрит на ответ.

Если сервер возвращает одновременно HTTP 500 и текст `SQLITE_ERROR`,
Nuclei записывает находку — сайт показывает внутреннюю ошибку базы данных.

Это ещё не подтверждение SQL-инъекции.

## Что получилось проверить

- Nuclei принимает шаблон и находит ошибку на локальном Juice Shop.
- Проверка работает через общий запуск проекта.
- Находка появляется в `findings.json` и `report.md`.
- В моём запуске получилось четыре находки, без использования DeepSeek.

Для сравнения проверил обычный поиск и ввод с двумя кавычками:

| Поисковая строка | HTTP-код | Результат |
|---|---|---|
| `apple` | 200 | Три товара, ошибки SQLite нет |
| `apple'` | 500 | Есть `SQLITE_ERROR` |
| `apple''` | 200 | Пустой список, ошибки SQLite нет |

Отдельный случай «HTTP 500 без SQLITE_ERROR» пока не проверял.

## Как запустить

Нужны Docker Desktop или Docker Engine и Docker Compose.
Все команды ниже выполняются в Bash — например, в терминале WSL.

Открой папку проекта. В текущей ветке должен быть файл
`config/nuclei/juice-shop-sqlite-error.yaml`.

### 1. Запустить Juice Shop

Сначала задаём пользователя для контейнера, чтобы он мог сохранять
отчёты в наши папки. Эти переменные действуют в текущем терминале.

```bash
export AGENT_UID="$(id -u)"
export AGENT_GID="$(id -g)"
```

Создаём папки для результатов и запускаем сайт:

```bash
mkdir -p runs logs reports
docker compose up -d juice-shop
docker compose ps juice-shop
```

Дождись запуска и открой http://localhost:3000.

### 2. Собрать образ агента

```bash
docker compose build agent
```

При сборке внутрь образа копируются код проекта и YAML-шаблоны.
Если изменил шаблон, перед следующим запуском нужно пересобрать образ.

Первая сборка может занять несколько минут.

### 3. Проверить YAML

```bash
docker compose --profile agent run --rm --no-deps \
  -e HOME=/tmp --entrypoint nuclei agent \
  -validate \
  -t /agent/config/nuclei/juice-shop-sqlite-error.yaml \
  -disable-update-check
```

Здесь запускается сам Nuclei и проверяет, правильно ли написан шаблон.
Запросов к сайту на этом шаге нет.

Если всё нормально, в конце будет:

```text
All templates validated successfully
```

`HOME=/tmp` нужен, чтобы Nuclei мог записать свои настройки.

### 4. Запустить только этот шаблон

```bash
docker compose --profile agent run --rm --no-deps \
  -e HOME=/tmp --entrypoint nuclei agent \
  -u http://juice-shop:3000 \
  -t /agent/config/nuclei/juice-shop-sqlite-error.yaml \
  -disable-update-check -no-interactsh
```

Теперь Nuclei отправляет запрос к поиску и проверяет ответ.

При срабатывании появится строка примерно такого вида:

```text
[juice-shop-search-sqlite-error] [http] [low] http://juice-shop:3000/rest/products/search?q=apple%27
```

`%27` — это одинарная кавычка в адресе запроса.

Из контейнера сайт доступен по адресу `http://juice-shop:3000`.
В браузере на компьютере используем `http://localhost:3000`.

### 5. Запустить все DAST-шаблоны через проект

```bash
docker compose --profile agent run --rm --no-deps \
  agent scan --benchmark juice-shop --mode dast --no-llm
```

Этот запуск проверяет сайт шаблонами из `config/nuclei/`,
включая новый, и собирает общий отчёт.

`--no-llm` означает, что DeepSeek не используется.

В конце программа напечатает путь к результатам:

```text
runs/<ID>/reports/report.md
runs/<ID>/reports/findings.json
runs/<ID>/reports/summary.json
```

`<ID>` — папка конкретного запуска, её название будет в выводе терминала.

В `report.md` и `findings.json` ищем:

```text
Juice Shop search SQLite error disclosure
```

В моём запуске было четыре находки. После изменения шаблонов или версии
Juice Shop количество может отличаться.

## Если не получается сохранить отчёт

У меня была ошибка:

```text
Cannot create run directory; check mount permissions
```

Проверить владельцев папок можно так:

```bash
id
ls -ld runs logs reports
```

В моём случае папка `runs` принадлежала `root`, поэтому контейнер
не мог записать туда результат. Исправил владельца этой папки:

```bash
sudo chown "$(id -u):$(id -g)" runs
```

Эту команду нужно выполнять только если проверка показала такую же проблему.
После исправления можно повторить общий DAST-запуск.

## Что ещё нужно сделать

- Проверить, что шаблон не срабатывает на HTTP 500 без ошибки SQLite.
- Проверить, что HTTP 200 с текстом SQLITE_ERROR тоже не даёт находку.
- Попросить другого участника повторить запуск по этой инструкции.

Шаблон проверяет только поиск Juice Shop.
Отсутствие срабатывания не означает, что весь сайт безопасен.