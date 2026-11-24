"""Single CTF tool-loop engine: session, gateway, tools, loop, fallbacks.

Everything the seven former standalone agents shared lives here once:
environment plumbing, the safe materials guard, the guarded HTTP layer
(GET/POST/batch with cookie capture, secret-line and base64-flag extraction),
the LLM gateway with retries, the JSON action contract, the main loop with
repeat and deadline guards, finish validation against live evidence, and the
graceful fallback writers. Profile-specific matrices and hints come from
:data:`app.agent.ctf.profiles.PROFILES`.
"""

from __future__ import annotations

import base64
import collections
import concurrent.futures
import hashlib
import html as html_mod
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

FLAG_RX = re.compile(r"(?i)(?:[a-z][a-z0-9_]{1,24})\{[^\r\n{}]{2,250}\}")
SECRET_LINE_RX = re.compile(
    r"(?im)(?:flag|secret|флаг|секрет|ключ|токен|token|ответ|answer|код)"
    r"[^\r\n]{0,60}?[:=\-]\s*([^\r\n<>]{4,200})"
)
B64_CANDIDATE_RX = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

REPEAT_LIMIT = 4


def clip(text, limit=13000):
    text = str(text)
    if len(text) <= limit:
        return text
    half = limit // 2
    return (
        text[:half] + f"\n...[truncated {len(text) - limit} chars]...\n" + text[-half:]
    )


def clean_secret_value(v):
    """Format-agnostic secret capture with decoy/HTML-fragment filtering."""
    v = re.sub(r"<[^>]+>", "", str(v))
    v = html_mod.unescape(v).strip().strip("\"'`").strip()
    if len(v) < 4 or len(v) > 200:
        return ""
    # A real secret never carries quotes, angle brackets, backslashes or
    # attribute syntax; '=' is allowed only as trailing base64 padding.
    if re.search(r"[\"'<>`\\]", v):
        return ""
    if re.search(
        r"(?i)\b(action|method|class|href|src|input|form|submit|value|name)\s*=", v
    ):
        return ""
    if "://" in v or v.startswith("/"):
        return ""
    if "=" in v.rstrip("="):
        return ""
    if v.lower() in (
        "true",
        "false",
        "null",
        "none",
        "undefined",
        "admin",
        "password",
        "login",
        "username",
        "user",
        "test",
        "flag",
        "secret",
        "token",
        "submit",
        "войти",
        "выход",
    ):
        return ""
    return v[:200]


class GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only inside the resolved target origin."""

    def __init__(self, session):
        super().__init__()
        self._session = session

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        t = urllib.parse.urlsplit(self._session.target)
        g = urllib.parse.urlsplit(newurl)
        if (g.hostname, g.port, g.scheme) != (t.hostname, t.port, t.scheme):
            raise urllib.error.HTTPError(
                newurl, 403, "redirect outside target", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Session:
    """Mutable run state: env, evidence, caches, route and cookie."""

    def __init__(self, profile, env=None):
        env = os.environ if env is None else env
        self.profile = profile
        self.task_dir = Path(env.get("CTF_TASK_DIR", ".")).expanduser().resolve()
        materials = self.task_dir / "materials"
        self.materials = materials if materials.is_dir() else self.task_dir
        self.out_dir = Path(env.get("CTF_ARTIFACT_DIR", ".")).expanduser()
        self.target = env.get("CTF_TARGET_URL", "http://target:8000").rstrip("/")
        self.deadline = time.monotonic() + profile.deadline_seconds
        self.max_steps = int(env.get("CTF_AGENT_MAX_STEPS", str(profile.max_steps)))
        self.evidence = {
            "http": collections.deque(maxlen=80),
            "file": collections.deque(maxlen=80),
        }
        self.http_cache = collections.OrderedDict()
        self.route = ""
        self.routes = []
        self.session_cookie = ""
        self.last_probe = {}
        self.candidates = []  # (priority, value) — git-history recovery
        self.current_nonempty_lines = set()

    # -- evidence ---------------------------------------------------------
    def remember(self, text, channel="http"):
        """Store raw evidence; base64-hidden flags are decoded and appended.

        The git-forensics family stores into the same channel it reads
        back from (``verified_flag`` scans "http"), so decoded hits land there
        regardless of the caller's channel.
        """
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        s = str(text)
        if not s:
            return
        self.evidence[channel].append(s[:500000])
        for hit in self.decode_b64_flags(s):
            self.evidence["http"].append(hit)

    def decode_b64_flags(self, text):
        """Surface flags hidden in base64 blobs inside honest responses."""
        extra = []
        for candidate in B64_CANDIDATE_RX.findall(text)[:12]:
            try:
                decoded = base64.b64decode(
                    candidate + "=" * ((-len(candidate)) % 4)
                ).decode("utf-8", "ignore")
            except ValueError:
                continue
            hit = FLAG_RX.search(decoded)
            if hit and hit.group() not in extra:
                extra.append(hit.group())
                self.evidence["http"].append(decoded)
        return extra

    def add_candidate(self, val, priority=1):
        val = str(val).strip()
        if not val or "\n" in val or len(val) > 400:
            return
        self.candidates.append((priority, val))

    def best_candidate(self):
        if not self.candidates:
            return ""
        self.candidates.sort(key=lambda x: x[0], reverse=True)
        return self.candidates[0][1]

    def best_evidence_value(self):
        for record in self.evidence["http"]:
            m = FLAG_RX.search(record)
            if m:
                return m.group()
        return ""

    def verified_flag(self, flag):
        return any(flag in record for record in self.evidence["http"])

    # -- materials guard --------------------------------------------------
    def safe_material_path(self, rel):
        """realpath + strict parent check: sibling/symlink escapes rejected."""
        base = Path(os.path.realpath(self.materials))
        p = Path(os.path.realpath(os.path.join(base, str(rel).lstrip("/"))))
        # strict containment inside materials only (a substring test would
        # pass "<MATERIALS>2/x"; realpath resolves symlinks first)
        if p != base and base not in p.parents:
            raise ValueError("path outside task")
        return p

    def walk_materials(self, cap=3000, max_depth=8):
        result = []
        base = self.materials
        if not base.is_dir():
            return result
        for root, dirs, names in os.walk(base):
            dirs[:] = sorted(
                x
                for x in dirs
                if x != ".git" and len(Path(root).relative_to(base).parts) < max_depth
            )
            for name in sorted(names):
                p = Path(root) / name
                if p.is_file():
                    result.append(p)
                    if len(result) >= cap:
                        return result
        return result

    def public_names(self, limit=8):
        """Filenames the service serves honestly — the reconnaissance seed."""
        names = []
        for p in self.walk_materials():
            if p.name == "instruction.md":
                continue
            names.append(p.name)
        for extra in (
            "notes.txt",
            "readme.md",
            "index.html",
            "policy.txt",
            "info.txt",
            "guide.txt",
        ):
            if extra not in names:
                names.append(extra)
        return names[:limit]

    def read_instruction(self):
        for loc in (
            self.task_dir / "instruction.md",
            self.materials / "instruction.md",
        ):
            try:
                if loc.is_file():
                    return loc.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return ""

    # -- HTTP layer -------------------------------------------------------
    def valid_http_path(self, path):
        path = str(path)
        if not path.startswith("/") and not path.startswith("?"):
            raise ValueError("relative path must start with / or ?")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in path) or len(path) > 1400:
            raise ValueError("invalid path")
        if "#" in path:
            path = path.split("#", 1)[0]
        return path.replace(" ", "%20")

    def _opener(self):
        if not hasattr(self, "_opener_instance"):
            self._opener_instance = urllib.request.build_opener(GuardedRedirect(self))
        return self._opener_instance

    def set_opener(self, opener):
        """Test/injection seam: replace the guarded HTTP opener."""
        self._opener_instance = opener

    def _headers_with_cookie(self, extra=None):
        h = {"User-Agent": "CTF-Agent/1.0", "Accept": "*/*"}
        if self.session_cookie:
            h["Cookie"] = self.session_cookie
        if extra:
            h.update(extra)
        return h

    def _capture_cookie(self, hdr):
        raw = hdr.get("Set-Cookie") or hdr.get("set-cookie")
        if raw and not self.session_cookie:
            self.session_cookie = raw.split(";")[0].strip()

    def _try_decode_value(self, v):
        """Peel url/base64/json layers off a cookie or token value."""
        cur = str(v).strip()
        chain = []
        for _ in range(3):
            if "%" in cur:
                try:
                    cur = urllib.parse.unquote_plus(cur)
                    chain.append("url")
                    continue
                except Exception:
                    pass
            if len(cur) >= 8 and re.fullmatch(r"[A-Za-z0-9\-_]+=*", cur):
                try:
                    pad = cur + "=" * (-len(cur) % 4)
                    dec = base64.urlsafe_b64decode(pad).decode("utf-8", "replace")
                    if "{" in dec and "}" in dec and len(dec) < 400:
                        cur = dec
                        chain.append("b64")
                        continue
                except Exception:
                    pass
            break
        if not chain:
            return ""
        return cur, "+".join(chain)

    def unwrap_body(self, text):
        """Return the inner file body if the response wraps it in JSON/<pre>."""
        t = text.strip()
        if t.startswith("{") and t.endswith("}"):
            try:
                o = json.loads(t)
                if isinstance(o, dict) and len(o) <= 3:
                    # "file"/"name" keys often hold the FILE NAME, not the body
                    for k in (
                        "content",
                        "data",
                        "text",
                        "body",
                        "contents",
                        "value",
                        "file",
                    ):
                        v = o.get(k)
                        if isinstance(v, str) and v.strip():
                            return v
                if isinstance(o, dict):
                    strs = [v for v in o.values() if isinstance(v, str) and v.strip()]
                    if len(strs) == 1:
                        return strs[0]
            except ValueError:
                pass
        m = re.search(r"<pre[^>]*>(.*)</pre>", t, re.I | re.S)
        if m and m.group(1).strip():
            return html_mod.unescape(m.group(1)).strip()
        return ""

    def _response_record(self, path, status, hdr, data, final_url=None):
        text = data.decode("utf-8", "replace")
        rx_hits = FLAG_RX.findall(text)[:8]
        rx_hits.extend(self.decode_b64_flags(text))
        # flags may hide in headers (Location, X-*) or in the redirect target
        for hv in list(hdr.values()) + ([final_url] if final_url else []):
            for v in FLAG_RX.findall(str(hv))[:3]:
                if v not in rx_hits:
                    rx_hits.append(v)
        secret_lines = []
        for m in SECRET_LINE_RX.finditer(text):
            val = clean_secret_value(m.group(1))
            if val and val not in secret_lines and not FLAG_RX.fullmatch(val):
                secret_lines.append(val)
            if len(secret_lines) >= 6:
                break
        rec = {
            "path": path,
            "status": status,
            "bytes": len(data),
            "content_type": hdr.get("Content-Type", hdr.get("content-type", "")),
            "sha1": hashlib.sha1(data).hexdigest()[:14],
            "flag_shaped_values": rx_hits,
            "preview": clip(text, 11000),
        }
        if len(text) > 11000:
            rec["tail"] = clip(text[-3000:], 3000)
        if secret_lines:
            rec["secret_lines"] = secret_lines
        if final_url:
            rec["final_url"] = final_url
        loc = hdr.get("Location") or hdr.get("location")
        if loc:
            rec["location"] = loc
        cookie = hdr.get("Set-Cookie") or hdr.get("set-cookie")
        if cookie:
            cv = cookie.split(";")[0].strip()
            rec["set_cookie"] = cv
            dec = self._try_decode_value(cv.split("=", 1)[1] if "=" in cv else cv)
            if isinstance(dec, tuple):
                rec["cookie_decoded"] = dec[0]
                rec["cookie_encoding"] = dec[1]
        inner = self.unwrap_body(text)
        if inner and inner.strip() != text.strip():
            rec["unwrapped_body"] = clip(inner, 11000)
        if status in range(200, 400):
            self.evidence["http"].append(text)
        return rec

    def http_get(self, path, method="GET", headers=None):
        path = self.valid_http_path(path)
        method = str(method).upper()
        if method not in ("GET", "HEAD"):
            raise ValueError("Only GET and HEAD")
        url = self.target + ("/" + path if path.startswith("?") else path)
        req = urllib.request.Request(
            url,
            method=method,
            headers=self._headers_with_cookie(dict(headers or {})),
        )
        try:
            with self._opener().open(
                req, timeout=min(6, max(1, int(self.deadline - time.monotonic() - 4)))
            ) as r:
                data = r.read(2_500_000) if method == "GET" else b""
                status, hdr, final = r.status, dict(r.headers), r.url
        except urllib.error.HTTPError as e:
            status = e.code
            hdr = dict(e.headers) if e.headers else {}
            data = e.read(150000) if method == "GET" else b""
            final = url
        except Exception as e:  # never raise: timeouts, DNS, bad URL
            return {"path": path, "error": type(e).__name__ + ": " + str(e)[:180]}
        self.http_cache[path] = data
        self.http_cache.move_to_end(path)
        while len(self.http_cache) > 30:
            self.http_cache.popitem(last=False)
        self._capture_cookie(hdr)
        return self._response_record(path, status, hdr, data, final)

    def http_post(self, action):
        """POST a form; redirect NOT followed — capture Set-Cookie/Location.
        "data" (str) is sent VERBATIM (duplicate params survive — HPP)."""
        path = self.valid_http_path(action.get("path", "/login"))
        fields = action.get("fields") if isinstance(action.get("fields"), dict) else {}
        raw_data = action.get("data") if isinstance(action.get("data"), str) else ""
        if not fields and not raw_data:
            raw = action.get("body") or ""
            if isinstance(raw, str) and raw.strip():
                fields = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
        extra_headers = {
            "Content-Type": str(
                action.get("content_type") or "application/x-www-form-urlencoded"
            )
        }
        for k, v in (action.get("headers") or {}).items():
            if str(k).lower() not in ("content-length", "host", "connection"):
                extra_headers[str(k)] = str(v)[:500]
        if action.get("json"):
            body = json.dumps(action.get("json"), ensure_ascii=False).encode("utf-8")
            extra_headers["Content-Type"] = "application/json"
        elif raw_data.strip():
            body = raw_data.encode("utf-8")  # VERBATIM (duplicate params stay)
        else:
            body = urllib.parse.urlencode(fields, doseq=True).encode("utf-8")
        url = self.target + ("/" + path if path.startswith("?") else path)
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers=self._headers_with_cookie(extra_headers),
        )
        try:
            with self._opener().open(
                req, timeout=min(8, max(1, int(self.deadline - time.monotonic() - 4)))
            ) as r:
                status, hdr = r.status, dict(r.headers)
                data = r.read(2_500_000)
        except urllib.error.HTTPError as e:
            status = e.code
            hdr = dict(e.headers) if e.headers else {}
            data = e.read(300000)
        except Exception as e:  # never raise
            return {"path": path, "error": type(e).__name__ + ": " + str(e)[:180]}
        self._capture_cookie(hdr)
        rec = self._response_record(path, status, hdr, data)
        rec["sent_fields"] = {k: str(v)[:200] for k, v in fields.items()}
        return rec

    def http_batch(self, action, cap=120, summarize=True):
        paths = action.get("paths", [])
        if not isinstance(paths, list):
            return "paths must be a list"
        valid = []
        for p in paths[:cap]:
            try:
                valid.append(self.valid_http_path(p))
            except ValueError:
                continue
        valid = list(dict.fromkeys(valid))
        if not valid:
            return "No valid paths"
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(self.http_get, valid))
        if not summarize:
            return results
        counts = collections.Counter((r.get("status"), r.get("sha1")) for r in results)
        interesting = []
        for r in results:
            if "error" in r:
                continue
            if r["status"] != 404 and r["status"] >= 200:
                keys = ("path", "status", "bytes", "sha1", "flag_shaped_values")
                if r.get("unwrapped_body"):
                    keys += ("unwrapped_body",)
                item = {k: r.get(k) for k in keys}
                rare = counts[(r["status"], r["sha1"])] <= 5
                # repeated bodies still carry a SHORT preview: the model must
                # see the source/secret
                item["preview"] = r.get("preview", "")[
                    : 900
                    if rare or r.get("flag_shaped_values") or r.get("unwrapped_body")
                    else 300
                ]
                interesting.append(item)
        interesting.sort(
            key=lambda r: (
                not bool(r.get("flag_shaped_values")),
                r.get("status", 999) != 200,
            )
        )
        return {
            "checked": len(valid),
            "status_counts": dict(
                collections.Counter(str(r.get("status", "ERR")) for r in results)
            ),
            "non_404": interesting[:80],
            "note": "soft-404 pages may share one sha1; unique bodies matter",
        }

    def distinct(self, results, homepage_sha=None):
        """200s whose body differs from the homepage/index boilerplate."""
        return [
            h
            for h in results.get("non_404", [])
            if h.get("status") == 200
            and (not homepage_sha or h.get("sha1") != homepage_sha)
        ]

    def resolve_target(self):
        """The real endpoint may be documented in instruction.md — probe every
        URL from env and materials, keep the first that answers."""
        candidates = []
        env_url = os.environ.get("CTF_TARGET_URL", "").strip().rstrip("/")
        if env_url:
            candidates.append(env_url)
        rx = re.compile(r"https?://[A-Za-z0-9_.\-]+(?::\d+)?(?:/[^\s\"'<>\\)\]]*)?")
        local, seen = [], set(candidates)
        probe_files = list(self.walk_materials()) + [
            self.task_dir / "instruction.md",
            self.materials / "instruction.md",
        ]
        for p in probe_files:
            try:
                if not p.is_file() or p.stat().st_size > 200000:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
                for m in rx.finditer(text):
                    u = m.group().rstrip(".,;)\"'").rstrip("/")
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    if re.search(r"(?i)://(localhost|127\.0\.0\.1|0\.0\.0\.0)", u):
                        local.append(u)
                    else:
                        candidates.append(u)
            except OSError:
                continue
        if self.target not in seen:
            candidates.append(self.target)
        candidates += local
        for u in candidates:
            if self._probe_url(u):
                if u != self.target:
                    print("target resolved to %s" % u, file=sys.stderr)
                    self.target = u
                return self.target
        return self.target

    @staticmethod
    def _probe_url(url, timeout=4):
        try:
            urllib.request.urlopen(urllib.request.Request(url + "/"), timeout=timeout)
            return True
        except urllib.error.HTTPError:
            return True  # an HTTP answer means the service is there
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return False

    # -- LLM gateway ------------------------------------------------------
    def model(self, messages):
        try:
            base = os.environ["OPENAI_BASE_URL"].rstrip("/")
            model_name = os.environ["LOCAL_AGENT_MODEL"]
            api_key = os.environ["OPENAI_API_KEY"]
        except KeyError as exc:
            raise RuntimeError(
                "CTF model gateway is not configured: missing environment variable "
                + str(exc)
            ) from None
        data = json.dumps(
            {"model": model_name, "messages": messages, "temperature": 0.1},
            ensure_ascii=False,
        ).encode("utf-8")
        headers = {
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
            "X-Agent-Session": os.environ.get("CTF_AGENT_SESSION_ID", ""),
        }
        error = None
        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    base + "/chat/completions",
                    data=data,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(
                    req,
                    timeout=min(90, max(10, int(self.deadline - time.monotonic()))),
                ) as resp:
                    answer = json.loads(resp.read().decode("utf-8"))["choices"][0][
                        "message"
                    ]["content"]
                if isinstance(answer, list):
                    answer = "".join(
                        x.get("text", "") for x in answer if isinstance(x, dict)
                    )
                if not isinstance(answer, str) or not answer.strip():
                    raise ValueError("empty model response")
                return answer
            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                ValueError,
                KeyError,
                IndexError,
            ) as exc:
                error = type(exc).__name__
                if attempt < 2 and time.monotonic() + 5 < self.deadline:
                    time.sleep(1.5 * (attempt + 1))
        raise RuntimeError("CTF model gateway error: " + str(error))

    @staticmethod
    def action_from_text(text):
        """Normalize every planner shape to one dict with a "tool" key."""
        t = str(text).strip()
        t = re.sub(r"<(think|analysis)>.*?</\1>", "", t, flags=re.I | re.S).strip()
        if t.startswith("```"):
            t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.I | re.S).strip()
        try:
            a = json.loads(t)
        except ValueError:
            decoder = json.JSONDecoder()
            objs = []
            for i, c in enumerate(t):
                if c == "{":
                    try:
                        obj, _ = decoder.raw_decode(t[i:])
                        if isinstance(obj, dict):
                            objs.append(obj)
                    except ValueError:
                        pass
            a = objs[-1] if objs else None
            if a is None:
                m = FLAG_RX.search(t)
                if m:
                    return {"tool": "finish", "flag": m.group()}
                return {"tool": "invalid", "reason": "Верни ОДИН JSON-объект с tool."}
        if not isinstance(a, dict):
            return {"tool": "invalid", "reason": "Need JSON object"}
        if isinstance(a.get("arguments"), dict):
            a.update(a.pop("arguments"))
        if isinstance(a.get("args"), dict):
            a.update(a.pop("args"))
        if "action" in a and "tool" not in a:
            a["tool"] = a["action"]
        return a

    # -- artifact ---------------------------------------------------------
    def write_artifact(self, val):
        self.out_dir.mkdir(parents=True, exist_ok=True)
        target = self.out_dir / "flag.txt"
        temporary = self.out_dir / ".flag.txt.tmp"
        temporary.write_text(str(val).strip(), encoding="utf-8")
        os.replace(temporary, target)

    def write_report(self, tried_finish=None):
        """Diagnostics next to flag.txt — trace a Wrong Answer from artifacts."""
        try:
            with open(self.out_dir / "report.txt", "wt", encoding="utf-8") as f:
                f.write("profile: %s\n" % self.profile.name)
                f.write(
                    "target: %s (env=%s)\n"
                    % (self.target, os.environ.get("CTF_TARGET_URL", ""))
                )
                f.write(
                    "session_cookie_captured: %s\n"
                    % ("yes" if self.session_cookie else "no")
                )
                f.write("evidence_responses: %d\n" % len(self.evidence["http"]))
                f.write("best_evidence_value: %r\n" % self.best_evidence_value()[:200])
                f.write(
                    "tried_finish: %s\n"
                    % json.dumps((tried_finish or [])[:10], ensure_ascii=False)
                )
                f.write(
                    "last_login_probe: %s\n"
                    % json.dumps(self.last_probe, ensure_ascii=False, default=str)[
                        :6000
                    ]
                )
                for i, rec in enumerate(list(self.evidence["http"])[-4:]):
                    f.write("--- response[%d]\n%s\n" % (i, clip(str(rec), 700)))
        except OSError:
            pass

    # -- main loop --------------------------------------------------------
    def initial_context(self):
        parts = ["PROFILE: " + self.profile.name, "INSTRUCTIONS: " + self.profile.hint]
        instruction = self.read_instruction()
        if instruction:
            parts.append("instruction.md:\n" + clip(instruction, 10000))
        parts.append("FILES:\n" + clip(self.profile.inventory(self), 9000))
        for p in self.walk_materials()[:10]:
            try:
                if p.stat().st_size > 12000 or p.suffix.lower() in (
                    ".gz",
                    ".zip",
                    ".png",
                    ".jpg",
                    ".pdf",
                ):
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
                parts.append(
                    "SAMPLE %s:\n%s" % (p.relative_to(self.materials), text[:1400])
                )
            except OSError:
                pass
        return clip("\n\n".join(parts), 20000)

    def run(self):
        """LLM loop with repeat guard, finish validation and graceful fallback."""
        os.makedirs(self.out_dir, exist_ok=True)
        # never leave a stale flag from a previous run: a checker reading the
        # artifact dir after a failed run must not see an old value
        try:
            (self.out_dir / "flag.txt").unlink()
        except OSError:
            pass
        for hook in self.profile.before_loop:
            try:
                hook(self)
            except Exception as e:  # never block the loop on a pre-step
                print(
                    "%s error: %s" % (hook.__name__, type(e).__name__), file=sys.stderr
                )
        try:
            ctx = self.initial_context()
        except Exception as e:  # materials may be weird; never block the loop
            ctx = (
                "PROFILE: "
                + self.profile.name
                + " (materials context error: "
                + type(e).__name__
                + ")"
            )
            print("initial_context error: " + type(e).__name__, file=sys.stderr)
        messages = [
            {
                "role": "system",
                "content": "Ты самостоятельный исследователь в разрешённой CTF-песочнице. "
                + self.profile.hint
                + "\n"
                + self.profile.tool_descriptions,
            },
            {
                "role": "user",
                "content": ctx + "\nНачни расследование. Сформируй одно действие JSON.",
            },
        ]
        recent_actions = collections.deque(maxlen=6)
        last_flag = ""
        tried_finish = []
        finish_attempts = 0
        history_window = self.profile.history_window
        for step in range(self.max_steps):
            if time.monotonic() > self.deadline - self.profile.reserve_seconds:
                break
            messages = messages[:2] + messages[2:][-history_window:]
            try:
                reply = self.model(messages)
            except RuntimeError as e:
                print(str(e), file=sys.stderr)
                break
            act = self.action_from_text(reply)
            name = str(act.get("tool", ""))
            messages.append({"role": "assistant", "content": reply[:3000]})
            if name in ("finish", "submit", "write_flag"):
                flag = str(
                    act.get("flag")
                    or act.get("value")
                    or act.get("secret")
                    or act.get("answer")
                    or act.get("result")
                    or ""
                ).strip()
                if flag and "\n" in flag:
                    flag = flag.splitlines()[0].strip()
                if flag and len(flag) <= 500:
                    finish_attempts += 1
                    last_flag = flag
                    verdict = self.profile.validate_finish(self, flag, finish_attempts)
                    if verdict.accepted:
                        self.write_artifact(flag)
                        self.write_report(tried_finish)
                        print("finish verified", file=sys.stderr)
                        return 0
                    if verdict.feedback_override is not None:
                        feedback = verdict.feedback_override
                        if verdict.steer_candidate:
                            tried_finish.append(flag)
                    else:
                        feedback = (
                            "Флаг НЕ найден в сохранённых ответах живого сервиса. Значение "
                            "должно быть ТОЧНО скопировано из тела ответа. Проверь ещё раз."
                        )
                else:
                    feedback = "Пустой или некорректный флаг. Скопируй точное значение из ответа сервиса."
            else:
                try:
                    result = self.profile.call_tool(self, act)
                    if isinstance(result, dict) and self.profile.note_tool_result:
                        self.profile.note_tool_result(self, name, result)
                    feedback = (
                        json.dumps(result, ensure_ascii=False)
                        if not isinstance(result, str)
                        else result
                    )
                except Exception as e:
                    feedback = "Tool error: " + type(e).__name__ + ": " + str(e)[:350]
                if name not in ("invalid", ""):
                    print("step %d: %s" % (step + 1, name), file=sys.stderr)
            signature = json.dumps(act, ensure_ascii=False, sort_keys=True)[:800]
            recent_actions.append(signature)
            if (
                len(recent_actions) >= REPEAT_LIMIT
                and len(set(list(recent_actions)[-REPEAT_LIMIT:])) == 1
            ):
                feedback += (
                    "\nТы повторил одно действие %d раз. Измени подход или вызывай "
                    "finish с подтверждённым значением." % REPEAT_LIMIT
                )
            messages.append(
                {
                    "role": "user",
                    "content": "Результат %s:\n%s\nСледующий шаг — ОДИН JSON-объект."
                    % (name, clip(feedback, 18000)),
                }
            )
        return self.profile.fallback(self, last_flag, tried_finish)


class FinishVerdict:
    """Result of a profile's finish validation."""

    def __init__(self, accepted=False, feedback_override=None, steer_candidate=False):
        self.accepted = accepted
        self.feedback_override = feedback_override
        self.steer_candidate = steer_candidate


def run_profile(profile, env=None) -> int:
    """Entry point for a CLI/standalone run of one profile."""
    session = Session(profile, env=env)
    try:
        return session.run()
    except Exception as err:
        print(
            "Agent error: " + type(err).__name__ + ": " + str(err)[:200],
            file=sys.stderr,
        )
        return profile.crash_fallback(session)
