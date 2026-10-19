# Надёжность LLM-компонентов

Версия 0.4.1 использует LLM только для Planner, enrichment, AI Brief и read-only
Chat Analyst. Scanner остаются источником находок; LLM не создаёт Finding, не
запускает команды и не меняет цель сканирования.

## Ограниченные ответы

Для Planner, Brief и Chat заданы отдельные token budgets. При обрезанном ответе
выполняется не более одного повторного запроса с требованием более краткой формы.
Chat сохраняет полезный частичный текст и возвращает статус
`completed_with_warnings`/`chat_response_truncated`. UI показывает предупреждение
и предлагает безопасные follow-up действия. Ошибка Brief не уничтожает scanner
findings и обычный отчёт.

## Структурированные контракты

Ответы provider проходят JSON extraction и Pydantic validation. Chat Analyst
использует компактные блоки `summary`, `confirmed_points`,
`assumptions_or_manual_checks` и `remediation_priorities`. В запрос передаются
сохранённые findings выбранного run, а не произвольные файлы или scanner arguments.

Authoritative metadata приложения не позволяет:

- повысить HIGH до CRITICAL без CRITICAL-находки;
- назвать предполагаемый риск доказанной эксплуатацией;
- сообщить, что completed enrichment отсутствовал;
- сослаться на неизвестный run или Finding ID;
- использовать текст LLM как команду или аргумент scanner.

## Offline-режим

`--no-llm` гарантирует нулевое число LLM requests. Если provider недоступен, scan,
нормализация, отчёты, история run и детерминированные ответы Chat продолжают
работать. Проверка реального provider выполняется только явно через doctor/UI и не
является частью автоматических тестов.

Настройки и сценарии запуска приведены в [README](../README.md), диагностика — в
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).
