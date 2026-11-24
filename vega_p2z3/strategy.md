# P2Z3: Проект помнит прошлое

## Цель
Восстановить удалённый из кода секрет по истории проекта в `VEGA_TASK_DIR/materials` и записать его точное значение в `VEGA_CTF_ARTIFACT_DIR/flag.txt`.

## Алгоритм
1. Прочитать переменные среды `VEGA_TASK_DIR`, `VEGA_CTF_ARTIFACT_DIR`, `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `LOCAL_AGENT_MODEL`, `VEGA_AGENT_SESSION_ID`.
2. Изучить `instruction.md`, найти пустые или очищенные файлы в `materials` и проверить историю Git (`git log --all --full-history -p`, `git cat-file --batch-all-objects`, `.git/objects`).
3. Отделить удалённый секрет от текущих непустых файлов-заглушек.
4. Записать подтверждённое значение без лишних пробелов в `VEGA_CTF_ARTIFACT_DIR/flag.txt`.

## Интеграция (v2)
Код перенесён в проект 1:1 с харденингом платформы: realpath-guard путей
материалов, атомарная запись flag.txt (tmp + os.replace), безопасная ошибка
конфигурации LLM вместо traceback и base64-автодекод флагов в наблюдениях
(`decode_b64_flags`). Фолбэк по кандидатам работает при любом исходе.