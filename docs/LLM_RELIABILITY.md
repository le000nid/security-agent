# Надёжность LLM-компонентов

Версия 0.4.1 использует LLM только для Planner, enrichment, AI Brief и read-only
Chat Analyst. Scanner остаются источником находок; LLM не создаёт Finding, не
запускает команды и не меняет цель сканирования.

## Два режима completion

Planner, intent router, enrichment и AI Brief используют `complete_json`: запрос
включает JSON mode, а результат проходит extraction и Pydantic validation.
Обрезанный JSON не исполняется и не считается валидным.

Chat Analyst использует `complete_text`: `response_format` не отправляется, а
пользователь получает обычный `message.content` с абзацами. Hidden reasoning и
tool calls не выводятся. Для компонентов заданы отдельные token budgets. При
обрезанном Chat-ответе выполняется один повтор с просьбой дать завершённый ответ
с меньшим количеством повторов. Непустая полезная часть сохраняется и получает статус
`completed_with_warnings`/`chat_response_truncated`. UI показывает предупреждение
и предлагает безопасные follow-up действия. Ошибка Brief не уничтожает scanner
findings и обычный отчёт.

## Структурированные контракты

Основной результат Chat Analyst — поле `answer`. Старые блоки `summary`,
`confirmed_points`, `assumptions_or_manual_checks` и `remediation_priorities`
сохранены как optional UI-contract для совместимости с прежними ответами. В запрос
передаются сохранённые findings выбранного run, а не произвольные файлы или scanner
arguments.

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
