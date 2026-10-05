# security-agent

## Запуск Juice Shop на macOS

Понадобится установленный Docker Desktop. Запустите его и дождитесь готовности
Docker, затем откройте терминал в папке `security-agent`, где находится
`docker-compose.yml`.

```bash
docker compose up -d juice-shop
```
Откройте учебный сайт: http://localhost:3000.

Проверить состояние контейнера:

```bash
docker compose ps juice-shop
```

Остановить сайт:

```bash
docker compose stop juice-shop
```

Повторный запуск выполняется той же командой `docker compose up -d juice-shop`.
