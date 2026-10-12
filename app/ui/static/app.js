"use strict";
const $ = id => document.getElementById(id);
let benchmarks = [], selectedRun = null, allFindings = [], rationales = {};
let chatRuns = [], chatFindings = [], chatBusy = false;
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const statuses = {
  completed: "завершено", completed_with_warnings: "завершено с предупреждениями",
  completed_with_retries: "завершено после повторных запросов",
  completed_with_failures: "завершено с частичными ошибками", failed: "ошибка",
  skipped: "пропущено", running: "выполняется", not_started: "не начато",
  queued: "в очереди", rejected: "ответ отклонён", available: "доступно",
  unavailable: "недоступно", unchecked: "не проверено"
};
const stages = {sast:"SAST", dast:"DAST", enrichment:"Обогащение", ai_brief:"Итог ИИ", report:"Отчёт"};
const actions = {
  RUN_SAST:"Проверка исходного кода (SAST)", RUN_DAST:"Проверка HTTP-сервиса (DAST)",
  ENRICH_FINDINGS:"Обогащение находок", GENERATE_AI_BRIEF:"Формирование итога ИИ",
  GENERATE_REPORT:"Сохранение отчёта", FINISH:"Завершение",
  INVALID:"Некорректное решение", run_created:"Создание запуска",
  run_completed:"Завершение запуска", stage_started:"Начало этапа",
  stage_completed:"Завершение этапа", stage_warning:"Предупреждение этапа"
};
const decisionSources = {
  llm_planner:"Решение LLM Planner",
  deterministic_single_option:"Автоматически: единственный допустимый шаг",
  deterministic:"Фиксированная последовательность"
};
const errors = {
  llm_unavailable:"LLM недоступен или подключение чата не проверено. Доступны локальные фильтры и обычное сканирование без ИИ.",
  llm_preflight_failed:"Проверка доступности LLM не пройдена.",
  llm_busy:"LLM уже обрабатывает запрос. Дождитесь ответа.",
  agent_requires_llm:"Для режима «ИИ-агент» включите ИИ. Обычное сканирование работает без него.",
  scan_already_running:"Анализ уже выполняется. Дождитесь завершения.",
  run_not_found:"Сохранённый запуск не найден. Сначала выполните анализ.",
  run_unreadable:"Не удалось прочитать результаты запуска.",
  finding_not_found:"Эта находка отсутствует в выбранном запуске.",
  invalid_run_id:"Некорректный идентификатор запуска.",
  job_not_found:"Задача недоступна после перезапуска. Проверьте историю сохранённых запусков.",
  csrf_failed:"Защитный токен страницы устарел. Обновите локальную страницу.",
  brief_response_truncated:"Ответ для итога ИИ обрезан провайдером; результаты сканеров сохранены.",
  planner_response_truncated:"Ответ Planner обрезан. Повтор ограничен бюджетом запросов.",
  chat_response_truncated:"Распознавание запроса обрезано. Выберите сохранённый запуск для анализа или готовое действие чата. Подключение сохранено.",
  chat_json_invalid:"ИИ вернул некорректный JSON. Подключение сохранено.",
  chat_schema_invalid:"Ответ ИИ не прошёл проверку структуры или ссылок на находки. Подключение сохранено.",
  chat_context_mismatch:"Контекст ответа не совпал с выбранным запуском или находкой.",
  proposal_expired:"Предложение устарело, отменено или уже использовано. Запросите новый запуск.",
  benchmark_not_found:"Учебный стенд не найден в реестре.",
  benchmark_mode_not_supported:"Этот тип анализа не поддерживается выбранным стендом.",
  benchmark_required:"Выберите учебный стенд.",
  target_unreachable:"HTTP-стенд недоступен. Запустите его и проверьте doctor.",
  run_failed:"Запуск завершился с ошибкой. Проверьте сохранённый отчёт.",
  invalid_request:"Некорректный запрос.",
  internal_error:"Внутренняя ошибка. Сохранённые результаты остаются доступны.",
  chat_internal_error:"Не удалось обработать ответ помощника.",
  worker_unavailable:"Не удалось запустить обработчик анализа.",
  host_not_allowed:"Разрешён только локальный адрес.",
  request_too_large:"Запрос слишком большой.",
  unsupported_intent:"Это действие не поддерживается.",
  invalid_report_file:"Этот файл отчёта недоступен."
};
function node(tag, text, cls) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (cls) el.className = cls;
  return el;
}
function status(value) { return statuses[value] || "нет данных"; }
function errorText(code) { return (errors[code] || "Не удалось выполнить операцию.") + (code ? " (" + code + ")" : ""); }
function counts(data) { return Object.entries(data || {}).map(([key, value]) => key.toUpperCase() + ": " + value).join(" · ") || "нет"; }
function orchestration(value) { return value === "agent" ? "ИИ-агент" : "Обычное сканирование"; }
function notify(message) { $("notice").textContent = message; }
function fail(error) { notify(error.message || "Не удалось выполнить операцию."); }
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {
    method:"POST", headers:{"Content-Type":"application/json", "X-CSRF-Token":csrf}, body:JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(errorText(data.error));
  return data;
}
function show(id) {
  // A prior job's banner must not describe a different selected run or chat.
  notify("");
  document.querySelectorAll(".view").forEach(el => el.hidden = el.id !== id);
  document.querySelectorAll("nav>button").forEach(el => el.setAttribute("aria-current", el.dataset.view === id ? "page" : "false"));
  if (id === "runs") refreshRuns().catch(fail);
  if (id === "chat") refreshChatRuns().catch(fail);
}
document.querySelectorAll("[data-view]").forEach(b => b.onclick = () => show(b.dataset.view));
function selectBenchmark() {
  const benchmark = benchmarks.find(b => b.id === $("benchmark").value);
  $("mode").replaceChildren();
  if (!benchmark) return;
  const modes = benchmark.capabilities.length === 2 ? ["full", "sast", "dast"] : benchmark.capabilities;
  for (const mode of modes) {
    const option = node("option", mode.toUpperCase()); option.value = mode; $("mode").append(option);
  }
  $("benchmark-description").textContent = benchmark.description_ru || benchmark.description;
}
function llmControls() {
  const enabled = $("llm").checked;
  $("orchestration").querySelector('[value="agent"]').disabled = !enabled;
  if (!enabled) $("orchestration").value = "scan";
  for (const id of ["tone", "language", "evidence"]) $(id).disabled = !enabled;
}
$("benchmark").onchange = selectBenchmark;
$("llm").onchange = llmControls;
async function loadBenchmarks() {
  benchmarks = await api("/api/benchmarks");
  for (const b of benchmarks) {
    const option = node("option", b.name); option.value = b.id; $("benchmark").append(option);
    const card = node("article", undefined, "card");
    card.append(node("h2", b.name), node("p", b.description_ru || b.description),
      node("p", b.capabilities.map(c => c.toUpperCase()).join(" + "), "tag"),
      node("p", "Исходники: " + (b.source_path ? "есть" : "нет") + " · HTTP-сервис: " + (b.target_url ? "есть" : "нет")),
      node("p", b.expected_findings ? "Эталон ожидаемых находок: " + (b.baseline_count ?? "не прочитан") : "Эталон ожидаемых находок не задан"));
    const choose = node("button", "Выбрать стенд");
    choose.onclick = () => { $("benchmark").value = b.id; selectBenchmark(); show("guided"); };
    card.append(choose); $("benchmark-cards").append(card);
  }
  if (benchmarks.some(b => b.id === "demo-full")) $("benchmark").value = "demo-full";
  selectBenchmark();
}
function displayLLM(data) {
  $("llm-status").textContent = "Подключение чата к LLM: " + status(data.connectivity) + " · " + data.provider + " / " + data.model;
}
$("check-llm").onclick = async () => {
  $("check-llm").disabled = true;
  try { displayLLM(await api("/api/llm/check", {})); }
  catch (error) { fail(error); }
  finally { $("check-llm").disabled = false; }
};
$("scan-form").onsubmit = async event => {
  event.preventDefault(); notify(""); $("start").disabled = true;
  try {
    const job = await api("/api/scans", {
      benchmark_id:$("benchmark").value, mode:$("mode").value, orchestration:$("orchestration").value,
      llm_enabled:$("llm").checked, include_evidence_in_llm:$("llm").checked && $("evidence").checked,
      report_tone:$("tone").value, report_language:$("language").value
    });
    watchJob(job.job_id);
  } catch (error) { fail(error); $("start").disabled = false; }
};
function watchJob(id) {
  $("start").disabled = true; sessionStorage.setItem("activeJob", id);
  $("progress").hidden = false; $("open-result").hidden = true; pollJob(id);
}
async function pollJob(id) {
  try {
    const job = await api("/api/jobs/" + encodeURIComponent(id));
    $("job-status").textContent = status(job.status) + " · " + (job.run_id || "Создание запуска");
    $("events").replaceChildren(...job.events.map(e => node("li",
      (actions[e.action || e.event] || "Этап") + ": " + status(e.status) + " · находок: " + e.findings_count +
      (e.message ? " · " + errorText(e.message) : ""))));
    if (["queued", "running"].includes(job.status)) { setTimeout(() => pollJob(id), 1000); return; }
    sessionStorage.removeItem("activeJob"); $("start").disabled = false;
    if (job.run_id) {
      $("open-result").hidden = false; $("open-result").onclick = () => openRun(job.run_id).catch(fail);
    }
    notify(job.error ? errorText(job.error) : job.result?.summary?.ui_banner || "Анализ: " + status(job.status));
    refreshChatRuns().catch(fail);
  } catch (error) { sessionStorage.removeItem("activeJob"); $("start").disabled = false; fail(error); }
}
async function refreshRuns() {
  const runs = await api("/api/runs"); $("run-list").replaceChildren();
  if (!runs.length) { $("run-list").append(node("p", "Сохранённых запусков пока нет. Начните со сканирования.")); return; }
  for (const run of runs) {
    const card = node("article", undefined, "card");
    card.append(node("h2", run.benchmark_name || "Прямой запуск (старый формат)"),
      node("p", run.run_id, "muted"),
      node("p", status(run.status) + " · находок: " + run.total + " · " + (run.mode || "—").toUpperCase() + " / " + orchestration(run.orchestration)),
      node("p", counts(run.by_severity)));
    const open = node("button", "Открыть запуск"); open.onclick = () => openRun(run.run_id).catch(fail);
    card.append(open); $("run-list").append(card);
  }
}
$("refresh-runs").onclick = () => refreshRuns().catch(fail);
function renderComponents(el, run) {
  const components = run.llm_components;
  el.append(node("h3", "Компоненты ИИ"));
  if (!components) {
    el.append(node("p", "Старый формат: обогащение — " + status(run.llm_status) + "; запросов Planner: " + (run.planner_request_count || 0)));
    return;
  }
  const p = components.planner, e = components.enrichment, b = components.brief;
  el.append(node("p", "Planner: " + status(p.status) + " · запросов: " + p.requests + " · отклонённых ответов: " + p.failures),
    node("p", "Обогащение: " + status(e.status) + " · успешно: " + e.completed + " из " + e.requested + " · ошибок: " + e.failed),
    node("p", "Итог ИИ: " + status(b.status) + (b.error_code ? " · " + errorText(b.error_code) : "")));
  if (b.attempts?.length) {
    const detail = node("details"); detail.append(node("summary", "Безопасная диагностика AI Brief"));
    for (const attempt of b.attempts) {
      detail.append(node("p", "Попытка " + attempt.attempt + " · " + attempt.kind + " · бюджет " + attempt.max_tokens + " · " + (attempt.error_code || "completed") + " · finish_reason=" + (attempt.finish_reason || "unknown")));
      for (const issue of attempt.validation_issues || []) detail.append(node("p", issue.field + ": " + issue.type));
    }
    el.append(detail);
  }
}
async function openRun(id) {
  const safeId = encodeURIComponent(id);
  const [run, findings] = await Promise.all([api("/api/runs/" + safeId), api("/api/runs/" + safeId + "/findings")]);
  selectedRun = id; allFindings = findings; rationales = run.llm_rationales || {};
  $("run-title").textContent = run.benchmark_name || "Прямой запуск";
  $("run-meta").replaceChildren(node("p", id, "muted"), node("p", run.ui_banner),
    node("p", (run.mode || "—").toUpperCase() + " / " + orchestration(run.orchestration)),
    node("p", "Серьёзность: " + counts(run.by_severity)),
    node("p", "Этапы: " + Object.entries(run.stages || {}).map(([k,v]) => (stages[k] || k) + ": " + status(v)).join(" · ")),
    node("p", "Предупреждения: " + ((run.warnings || []).map(errorText).join("; ") || "нет")),
    node("p", "SAST: " + (run.source_path || "—") + " · DAST: " + (run.target_url || "—")),
    node("p", run.same_application ? "Исходники и HTTP-сервис одного проекта (из проверенного реестра)." : "Соответствие исходников и HTTP-сервиса не подтверждено либо выбран один тип анализа."));
  renderComponents($("run-meta"), run);
  if (run.benchmark_evaluation) {
    const b = run.benchmark_evaluation;
    $("run-meta").append(node("h3", "Покрытие учебного эталона"),
      node("p", "Ожидалось: " + b.expected_count + " · обнаружено: " + b.detected_expected_count + " · пропущено: " + b.missed_findings.length + " · вне эталона: " + b.unexpected_findings.length),
      node("small", "Это покрытие учебных примеров, а не показатель точности для реальных продуктов."));
  }
  renderBrief($("brief"), run.ai_brief || {status:run.ai_brief_status});
  $("trace").replaceChildren();
  for (const entry of run.trace || []) {
    const row = node("article", undefined, "card");
    row.append(node("h3", entry.step + ". " + (actions[entry.action] || entry.action)),
      node("p", decisionSources[entry.decision_source] || "Источник решения не указан"),
      node("p", status(entry.status) + " · добавлено находок: " + entry.findings_added));
    // Raw model reasoning is available in the downloadable trace; primary labels stay Russian.
    if (entry.error_code) row.append(node("p", errorText(entry.error_code)));
    $("trace").append(row);
  }
  $("downloads").replaceChildren();
  for (const filename of run.artifacts || []) {
    const a = node("a", "Скачать " + filename);
    a.href = "/api/runs/" + safeId + "/artifacts/" + encodeURIComponent(filename); a.download = filename;
    $("downloads").append(a);
  }
  const report = await fetch("/api/runs/" + safeId + "/artifacts/report.md");
  $("report").textContent = report.ok ? await report.text() : "Отчёт недоступен";
  $("severity").value = ""; $("source").value = "";
  const all = node("option", "Все категории"); all.value = ""; $("category").replaceChildren(all);
  for (const category of [...new Set(findings.map(f => f.normalized_category || f.category))].sort()) {
    const option = node("option", category); option.value = category; $("category").append(option);
  }
  $("finding-detail").hidden = true; renderFindings(); show("detail");
}
function renderFindings() {
  const findings = allFindings.filter(f =>
    (!$("severity").value || f.severity === $("severity").value) &&
    (!$("source").value || f.source === $("source").value) &&
    (!$("category").value || (f.normalized_category || f.category) === $("category").value));
  $("findings").replaceChildren();
  for (const f of findings) {
    const tr = node("tr"); tr.append(node("td", f.severity.toUpperCase(), "severity " + f.severity));
    const title = node("td"), button = node("button", f.title); button.onclick = () => findingDetail(f); title.append(button);
    tr.append(title, node("td", f.source + " / " + f.tool), node("td", f.normalized_category || f.category), node("td", f.location));
    $("findings").append(tr);
  }
  $("finding-count").textContent = "Показано находок: " + findings.length + " из " + allFindings.length;
}
["severity", "source", "category"].forEach(id => $(id).onchange = renderFindings);
function findingDetail(f) {
  const el = $("finding-detail"); el.hidden = false;
  el.replaceChildren(node("h2", f.title), node("p", f.id, "muted"),
    node("p", f.severity.toUpperCase() + " · уверенность: " + f.confidence),
    node("p", f.description), node("h3", "Рекомендация"), node("p", f.recommendation),
    node("h3", "Свидетельства"), node("pre", f.evidence || "Нормализованные свидетельства отсутствуют"),
    node("p", "Ссылка на сырой лог (не доступен через веб): " + f.raw_output_ref));
  if (rationales[f.id]) el.append(node("h3", "Краткое обоснование"), node("p", rationales[f.id]));
  const explain = node("button", "Объяснить в ИИ-помощнике");
  explain.onclick = () => selectChatContext(selectedRun, f.id).catch(fail);
  el.append(explain); el.scrollIntoView({behavior:"smooth", block:"nearest"});
}
function renderBrief(el, brief) {
  el.replaceChildren(node("h2", "Итог ИИ"));
  if (!brief.headline) {
    el.append(node("p", "Итог ИИ: " + status(brief.status)), node("small", "Доступность результатов сканеров и обычного отчёта указана в статусах этапов выше."));
    return;
  }
  el.append(node("h3", brief.headline), node("p", brief.overall_summary));
  for (const item of brief.top_findings || []) el.append(node("p", item.finding_id + " — " + item.why_it_matters));
  for (const step of brief.recommended_next_steps || []) el.append(node("p", "Следующий шаг: " + step));
  el.append(node("p", "Ограничения: " + brief.limitations), node("p", brief.closing_line));
}
async function refreshChatRuns(preferred, findingId) {
  const previousRun = preferred || $("chat-run").value;
  const previousFinding = findingId === undefined ? $("chat-finding").value : findingId;
  chatRuns = await api("/api/runs"); $("chat-run").replaceChildren();
  for (const run of chatRuns) {
    const option = node("option", (run.benchmark_name || "Прямой запуск") + " · " + run.run_id);
    option.value = run.run_id; $("chat-run").append(option);
  }
  if (chatRuns.some(r => r.run_id === previousRun)) $("chat-run").value = previousRun;
  await updateChatContext(previousFinding);
}
async function updateChatContext(findingId = "") {
  const id = $("chat-run").value, run = chatRuns.find(r => r.run_id === id);
  const all = node("option", "Весь запуск"); all.value = ""; $("chat-finding").replaceChildren(all);
  if (!run) { $("chat-context").textContent = "Запусков пока нет. Сначала выполните сканирование."; chatFindings = []; return; }
  $("chat-context").textContent = (run.benchmark_name || "Прямой запуск") + " · " + run.run_id + " · найдено проблем: " + run.total + " · " + status(run.status);
  const loaded = await api("/api/runs/" + encodeURIComponent(id) + "/findings");
  if ($("chat-run").value !== id) return;
  chatFindings = loaded;
  for (const finding of chatFindings) {
    const option = node("option", finding.severity.toUpperCase() + " · " + finding.title + " · " + finding.id);
    option.value = finding.id; $("chat-finding").append(option);
  }
  if (chatFindings.some(f => f.id === findingId)) $("chat-finding").value = findingId;
}
async function selectChatContext(runId, findingId = "") {
  await refreshChatRuns(runId, findingId);
  show("chat"); $("chat-message").focus();
}
$("chat-run").onchange = () => updateChatContext().catch(fail);
$("refresh-chat-runs").onclick = () => refreshChatRuns().catch(fail);
$("discuss-run").onclick = () => selectChatContext(selectedRun).catch(fail);
function chatEntry(label, message) {
  const el = node("article", undefined, "card"); el.append(node("strong", label), node("p", message));
  $("chat-history").append(el);
  while ($("chat-history").children.length > 30) $("chat-history").firstChild.remove();
  el.scrollIntoView({behavior:"smooth", block:"nearest"}); return el;
}
function findingLink(runId, findingId, title) {
  const button = node("button", title || findingId);
  button.onclick = async () => {
    try { await openRun(runId); const finding = allFindings.find(f => f.id === findingId); if (finding) findingDetail(finding); }
    catch (error) { fail(error); }
  };
  return button;
}
function chatReply(data) {
  const card = chatEntry("ИИ-помощник", data.message || "Сохранённые результаты");
  if (data.benchmarks) for (const b of data.benchmarks) card.append(node("p", b.name + " · " + b.id + " · " + b.capabilities.map(c => c.toUpperCase()).join(" + ")));
  if (data.summary) {
    const s = data.summary;
    card.append(node("p", s.run_id), node("p", (s.benchmark_name || "Прямой запуск") + " · " + status(s.status) + " · находок: " + s.total));
  }
  if (data.analysis) {
    const a = data.analysis;
    if (a.truncated) {
      const warning = node("p", a.notice || "Ответ сокращён из-за ограничения длины. Показана первая часть.", "chat-warning");
      warning.setAttribute("role", "status"); card.append(warning);
    }
    if (a.warnings?.includes("chat_claim_corrected")) card.append(node("p", "Противоречивые формулировки скорректированы по сохранённым данным.", "chat-warning"));
    if (a.summary) card.append(node("p", a.summary, "answer"));
    if (a.answer) card.append(node("p", a.answer, "answer"));
    for (const [key, title] of [["confirmed_points", "Подтверждено сканерами"], ["assumptions_or_manual_checks", "Требует ручной проверки"], ["remediation_priorities", "Почему это важно / приоритеты исправления"]]) {
      if (!a[key]?.length) continue;
      card.append(node("h3", title));
      const list = node("ul"); for (const point of a[key]) list.append(node("li", point)); card.append(list);
    }
    if (a.finding_facts?.length) {
      const facts = node("details"); facts.append(node("summary", "Сохранённая серьёзность находок (не оценка чата)"));
      for (const fact of a.finding_facts) facts.append(node("p", fact.title + " · " + fact.severity.toUpperCase() + " · " + fact.source));
      card.append(facts);
    }
    if (a.enrichment_status) card.append(node("small", "Обогащение в сохранённом запуске: " + status(a.enrichment_status)));
    if (a.exploit_validation_performed === false) card.append(node("p", "Эксплуатационная проверка не выполнялась."));
    if (a.previous_partial) {
      const prior = node("details"); prior.append(node("summary", "Первая часть исходного ответа (до повтора)"));
      prior.append(node("p", analysisText(a.previous_partial), "answer")); card.append(prior);
    }
    if (a.referenced_finding_ids.length) card.append(node("h3", "Связанные находки"));
    for (const id of a.referenced_finding_ids) card.append(findingLink(data.run_id, id, chatFindings.find(f => f.id === id)?.title || id));
    if (a.caveats.length) card.append(node("h3", "Ограничения"));
    for (const text of a.caveats) card.append(node("p", text));
    if (a.suggested_next_questions.length) card.append(node("h3", "Можно спросить дальше"));
    for (const question of a.suggested_next_questions) {
      const b = node("button", question); b.onclick = () => sendChat({message:question, run_id:data.run_id}, question); card.append(b);
    }
    if (a.truncated) {
      const followups = node("div", undefined, "actions");
      for (const [label, mode] of [["Продолжить", "continue"], ["Сжать ответ", "shorten"], ["Только подтверждённые факты", "confirmed"], ["Только то, что требует ручной проверки", "manual"]]) {
        if (a.follow_up_actions && !a.follow_up_actions.includes(mode)) continue;
        const button = node("button", label);
        button.onclick = () => sendChat({run_id:data.run_id, finding_id:data.finding_id || null,
          action:{intent:"ANALYZE_RUN"}, follow_up:mode, previous_answer:analysisText(a).slice(0,2400), message:data.question || "Анализ выбранного запуска"}, label);
        followups.append(button);
      }
      const one = node("button", "Разобрать по одной находке");
      one.onclick = async () => {
        try {
          await selectChatContext(data.run_id, "");
          const choices = chatEntry("ИИ-помощник", "Выберите находку для отдельного разбора:");
          for (const finding of chatFindings) {
            const button = node("button", finding.title + " · " + finding.severity.toUpperCase());
            button.onclick = () => sendChat({run_id:data.run_id, finding_id:finding.id,
              action:{intent:"EXPLAIN_FINDING"}, message:"Объясни наблюдение, условный риск и необходимую ручную проверку этой находки."}, finding.title);
            choices.append(button);
          }
        } catch (error) { fail(error); }
      };
      followups.append(one); card.append(followups);
    }
  }
  if (data.findings) {
    card.append(node("p", "Найдено по фильтру: " + data.findings.length));
    for (const f of data.findings) card.append(findingLink(data.run_id, f.id, f.severity.toUpperCase() + " · " + f.title + " · " + f.source));
  }
  if (data.finding) {
    const f = data.finding;
    card.append(node("h3", f.title), node("p", f.severity.toUpperCase() + " · " + f.source),
      node("p", f.description), node("p", "Рекомендация: " + f.recommendation));
    if (data.rationale) card.append(node("p", "Обоснование: " + data.rationale));
  }
  if (data.counts) card.append(node("p", counts(data.counts)));
  if (data.report) card.append(node("pre", data.report));
  if (data.proposal) {
    const p = data.proposal;
    card.append(node("h3", "Будет запущен анализ"), node("p", "Стенд: " + p.benchmark_name),
      node("p", "Тип: " + p.mode.toUpperCase() + " · режим: " + orchestration(p.orchestration) + " · ИИ: " + (p.llm_enabled ? "включён" : "отключён")));
    const start = node("button", "Запустить", "primary"), cancel = node("button", "Отмена");
    const confirm = async value => {
      start.disabled = cancel.disabled = true;
      try { handleChatData(await api("/api/chat/confirm", {proposal_id:p.proposal_id, confirm:value})); }
      catch (error) { chatEntry("ИИ-помощник", error.message); start.disabled = cancel.disabled = false; }
    };
    start.onclick = () => confirm(true); cancel.onclick = () => confirm(false);
    card.append(start, cancel);
  }
  return card;
}
function analysisText(analysis) {
  return [analysis.summary, analysis.answer, ...(analysis.confirmed_points || []),
    ...(analysis.assumptions_or_manual_checks || []), ...(analysis.remediation_priorities || [])].filter(Boolean).join("\n");
}
function handleChatData(data) {
  const card = chatReply(data);
  if (data.run_id) {
    const open = node("button", "Открыть запуск"); open.onclick = () => openRun(data.run_id).catch(fail); card.append(open);
  }
  if (data.job) {
    watchJob(data.job.job_id);
    const progress = node("button", "Показать ход анализа"); progress.onclick = () => show("guided"); card.append(progress);
  }
}
async function sendChat(payload, label) {
  if (chatBusy) return;
  const contextRun = payload.run_id || $("chat-run").value;
  const contextFinding = Object.prototype.hasOwnProperty.call(payload, "finding_id") ? payload.finding_id :
    (contextRun === $("chat-run").value ? $("chat-finding").value : "");
  if (contextRun) payload.run_id = contextRun;
  if (contextFinding) payload.finding_id = contextFinding;
  chatBusy = true; $("chat-form").querySelector("button").disabled = true;
  chatEntry("Вы", label);
  try { handleChatData(await api("/api/chat", payload)); }
  catch (error) { chatEntry("ИИ-помощник", error.message); }
  finally { chatBusy = false; $("chat-form").querySelector("button").disabled = false; }
  api("/api/llm").then(displayLLM).catch(fail);
}
document.querySelectorAll("[data-intent]").forEach(b => b.onclick = () => sendChat({action:{intent:b.dataset.intent}, message:b.textContent}, b.textContent));
$("chat-high").onclick = () => sendChat({action:{intent:"SHOW_FINDINGS", severity:"high"}}, "Показать HIGH");
$("chat-form").onsubmit = event => {
  event.preventDefault(); if (chatBusy) return;
  const message = $("chat-message").value; $("chat-message").value = ""; sendChat({message}, message);
};
llmControls(); loadBenchmarks().catch(fail); refreshChatRuns().catch(fail);
api("/api/llm").then(displayLLM).catch(fail);
const restored = sessionStorage.getItem("activeJob"); if (restored) watchJob(restored);
