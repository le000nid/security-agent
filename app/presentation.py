"""Russian UI summaries derived from actual outcomes, including legacy runs."""


def run_banner(run: dict) -> str:
    stages = run.get("stages", {})
    parts = [f"Найдено проблем: {run.get('total', 0)}."]
    labels = {"sast": "SAST", "dast": "DAST", "report": "Обычный отчёт"}
    for key, label in labels.items():
        if stages.get(key) == "failed":
            parts.append(f"{label}: ошибка этапа.")
    if run.get("status") == "failed":
        parts.append(
            "Запуск завершился с ошибкой; доступны только сохранённые результаты."
        )
    elif run.get("status") == "completed_with_warnings":
        parts.append("Анализ завершён с предупреждениями.")
    else:
        parts.append(
            "Анализ завершён."
            if run.get("status") == "completed"
            else "Анализ выполняется."
        )
    if run.get("llm_enabled") is False:
        parts.append("ИИ отключён. Обогащение и итог ИИ пропущены.")
    else:
        stats = run.get("enrichment", {})
        if stages.get("enrichment") in ("completed", "completed_with_failures"):
            parts.append(
                f"Обогащено находок: {stats.get('completed', 0)} из {stats.get('requested', 0)}."
            )
        if (
            "llm_preflight_failed" in run.get("warnings", [])
            or run.get("finish_reason") == "llm_preflight_failed"
        ):
            parts.append("LLM недоступен: проверка подключения не пройдена.")
        brief = run.get("llm_components", {}).get("brief", {})
        if stages.get("ai_brief") == "completed":
            parts.append("Итог ИИ сформирован.")
        elif stages.get("ai_brief") == "failed":
            if brief.get("error_code") == "brief_response_truncated":
                parts.append("Ответ для итога ИИ обрезан провайдером.")
            else:
                parts.append("Не удалось сформировать итог ИИ.")
            if stages.get("report") == "completed":
                parts.append("Обычный отчёт сохранён.")
    return " ".join(parts)
