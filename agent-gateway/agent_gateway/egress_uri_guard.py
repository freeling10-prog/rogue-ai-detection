"""Canonical SSRF and cloud-metadata URI guard for tool arguments.

Every URL, URI, or host string in a tool call's arguments is canonicalized
before it is classified, so the spelling of an address does not change the
decision. Covered spellings:

- dword / decimal (``2130706433``), hex (``0x7f000001``, ``0x7f.0.0.1``),
  octal (``0177.0.0.1``), short forms (``127.1``)
- IPv6 literals, including IPv4-mapped (``::ffff:127.0.0.1``,
  ``::ffff:7f00:1``), IPv4-compatible, NAT64 (``64:ff9b::/96``), zone ids
- URL userinfo confusion (``https://allowed.com@169.254.169.254``), and the
  backslash form some parsers read differently (``http://allowed.com\\@10.0.0.1``)
- percent-encoded hosts, a trailing dot, upper case
- wildcard-DNS names that embed an address (``127.0.0.1.nip.io``)
- cloud metadata names and addresses (``169.254.169.254``,
  ``metadata.google.internal``, ``fd00:ec2::254``, ``100.100.100.200``,
  ``169.254.170.2``)

Nothing is resolved: the guard makes no DNS or network call, so a public
name that later resolves to an internal address (DNS rebinding) is out of
scope here.

Verdicts:

- ``deny``: cloud metadata, any non-canonical spelling of an internal
  address, userinfo that hides an internal host, or a loopback / private
  target that is not on the lab allowlist where ``hold`` does not apply
- ``hold``: an RFC 1918 / link-local / ULA / CGNAT target written plainly; a
  bound one-time OOB approval releases it
- ``allow``: a public address or name, or a lab-allowlisted literal
  (``127.0.0.1``, ``localhost``, ``::1`` by default, so lab fixtures keep working)

Findings are logged as ``ssrf_boundary_violation`` (approximate AML.T0053).
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

ATLAS_SSRF = "AML.T0053"
DEFAULT_LAB_ALLOW = frozenset({"127.0.0.1", "localhost", "::1"})

URI_KEYS = frozenset({
    "url", "uri", "href", "endpoint", "host", "hostname", "target", "address", "addr",
    "callback", "callback_url", "webhook", "webhook_url", "redirect", "redirect_uri",
    "link", "src", "source_url", "base_url", "server", "proxy", "location",
    "urls", "uris", "hosts", "links", "targets", "endpoints",
})
_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{1,15}://[^\s\"'<>`]+")
_SCHEMELESS_RE = re.compile(r"^//")
_WILDCARD_DNS_RE = re.compile(
    r"^(?:.*?[.-])?((?:\d{1,3}[.-]){3}\d{1,3}|0x[0-9a-f]{8})\.(?:nip\.io|sslip\.io|xip\.io|nip\.direct|localtest\.me)$"
)

METADATA_HOSTS = frozenset({
    "metadata.google.internal", "metadata.goog", "metadata", "instance-data",
    "instance-data.ec2.internal", "metadata.azure.internal", "metadata.tencentyun.com",
    "metadata.packet.net",
})
METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("169.254.169.123"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("192.0.0.192"),
})
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".corp", ".home.arpa", ".lan")


@dataclass
class UriVerdict:
    verdict: str  # allow | hold | deny
    raw: str
    host: str = ""
    canonical: str = ""
    category: str = "public"
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict, "host": self.host[:200], "canonical": self.canonical,
            "category": self.category, "reasons": self.reasons,
            "atlas": ATLAS_SSRF, "atlas_approximate": True,
        }


def _parse_ipv4_part(part: str) -> Optional[int]:
    if not part:
        return None
    try:
        if part.lower().startswith("0x"):
            return int(part[2:] or "0", 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part, 8)
        if part.isdigit():
            return int(part, 10)
    except ValueError:
        return None
    return None


def parse_inet_aton(host: str) -> Optional[ipaddress.IPv4Address]:
    """inet_aton semantics: 1-4 parts, each decimal, 0x hex, or 0-prefixed octal."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = [_parse_ipv4_part(p) for p in parts]
    if any(n is None for n in nums):
        return None
    *head, last = nums
    if any(n > 255 for n in head):
        return None
    if last >= 256 ** (5 - len(nums)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (5 - len(nums)) + last
    if value > 0xFFFFFFFF:
        return None
    return ipaddress.IPv4Address(value)


def _embedded_v4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if int(ip) >> 32 == 0 and int(ip) > 1:  # IPv4-compatible ::a.b.c.d
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    return None


def canonical_ip(host: str) -> tuple[Optional[ipaddress._BaseAddress], bool]:
    """(address, was_obfuscated). ``was_obfuscated`` is True for any non-dotted-quad IPv4 spelling."""
    h = host.strip("[]")
    if "%" in h and ":" in h:
        h = h.split("%", 1)[0]  # IPv6 zone id
    if ":" in h:
        try:
            ip6 = ipaddress.IPv6Address(h)
        except ValueError:
            return None, False
        v4 = _embedded_v4(ip6)
        if v4 is not None:
            return v4, True
        return ip6, False
    try:
        plain = ipaddress.IPv4Address(h)
        return plain, False
    except ValueError:
        pass
    v4 = parse_inet_aton(h)
    if v4 is not None:
        return v4, True
    return None, False


def _category(ip: ipaddress._BaseAddress) -> str:
    if ip in METADATA_IPS:
        return "cloud_metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_link_local:
        return "link_local"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return "cgnat"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return "public"


def _hosts_for(raw: str) -> list[tuple[str, str, str]]:
    """(parser label, host, userinfo) under each parser reading of ``raw``."""
    text = raw.strip()
    if not _URL_RE.match(text) and not _SCHEMELESS_RE.match(text):
        # Bare host or host:port
        bare = text.split("/", 1)[0]
        user = ""
        if "@" in bare:
            user, bare = bare.rsplit("@", 1)
        if bare.startswith("["):
            host = bare[1:].split("]", 1)[0]
        elif bare.count(":") == 1:
            host = bare.split(":", 1)[0]
        else:
            host = bare
        return [("bare", host, user)]
    out = []
    for label, candidate in (("rfc3986", text), ("whatwg", text.replace("\\", "/"))):
        try:
            parts = urllib.parse.urlsplit(candidate)
        except ValueError:
            continue
        netloc = parts.netloc
        user = netloc.rsplit("@", 1)[0] if "@" in netloc else ""
        try:
            host = parts.hostname or ""
        except ValueError:
            host = ""
        if not host and netloc:
            host = netloc.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]")
        out.append((label, host, user))
    return out


def classify(raw: str, lab_allow: frozenset[str] = DEFAULT_LAB_ALLOW) -> UriVerdict:
    """Canonicalize one URI or host string and decide."""
    worst = UriVerdict("allow", raw=raw[:500])
    rank = {"allow": 0, "hold": 1, "deny": 2}
    for parser, host_raw, userinfo in _hosts_for(raw):
        host = urllib.parse.unquote(host_raw).strip().lower().rstrip(".")
        if not host:
            continue
        v = UriVerdict("allow", raw=raw[:500], host=host)
        reasons = v.reasons
        m = _WILDCARD_DNS_RE.match(host)
        embedded = None
        if m:
            embedded = m.group(1).replace("-", ".") if not m.group(1).startswith("0x") else m.group(1)
            reasons.append("wildcard_dns_embeds_address")
        ip, obfuscated = canonical_ip(embedded or host)
        if host in METADATA_HOSTS:
            v.category = "cloud_metadata"
            v.canonical = host
        elif ip is not None:
            v.canonical = str(ip)
            v.category = _category(ip)
            if obfuscated or embedded:
                reasons.append("non_canonical_address_encoding")
        elif host == "localhost" or host.endswith(".localhost"):
            v.category = "loopback"
            v.canonical = host
        elif host.endswith(_LOCAL_SUFFIXES):
            v.category = "internal_name"
            v.canonical = host
        else:
            v.canonical = host
        internal = v.category != "public"
        if internal and "%" in host_raw.split("%25", 1)[0] and ":" not in host:
            reasons.append("percent_encoded_host")
        if userinfo and internal:
            reasons.append("userinfo_hides_internal_host")
        if parser == "whatwg" and internal and "\\" in raw:
            reasons.append("backslash_parser_differential")
        if v.category == "cloud_metadata":
            reasons.append("cloud_metadata_target")
            v.verdict = "deny"
        elif not internal:
            v.verdict = "allow"
        elif reasons:
            v.verdict = "deny"
        elif host in lab_allow or v.canonical in lab_allow and host == v.canonical:
            v.verdict = "allow"
        elif v.category in ("private", "link_local", "cgnat", "internal_name"):
            reasons.append(f"{v.category}_target")
            v.verdict = "hold"
        else:
            reasons.append(f"{v.category}_target")
            v.verdict = "deny"
        if rank[v.verdict] > rank[worst.verdict] or (worst.host == "" and v.host):
            worst = v
    return worst


def iter_uri_candidates(arguments: Any, depth: int = 0, key: str = "") -> Iterator[tuple[str, bool]]:
    """(candidate, keyed). Keyed: the value of a URI-ish key. Else: a scheme:// inside free text."""
    if depth > 8:
        return
    if isinstance(arguments, dict):
        for k, v in list(arguments.items())[:64]:
            yield from iter_uri_candidates(v, depth + 1, str(k).lower())
    elif isinstance(arguments, (list, tuple)):
        for v in list(arguments)[:64]:
            yield from iter_uri_candidates(v, depth + 1, key)
    elif isinstance(arguments, str):
        s = arguments[:4096]
        leaf = key.rsplit(".", 1)[-1]
        if leaf in URI_KEYS and s.strip():
            yield s.strip(), True
            return
        for m in _URL_RE.finditer(s):
            yield m.group(0), False
    elif isinstance(arguments, int) and not isinstance(arguments, bool) and key in URI_KEYS:
        yield str(arguments), True  # {"host": 2130706433}


def inspect_arguments(arguments: Any, lab_allow: frozenset[str] = DEFAULT_LAB_ALLOW) -> Optional[UriVerdict]:
    """Most severe non-allow verdict across all URI candidates, or None.

    A plain private address mentioned inside free text (an email body linking
    an intranet page) is not a request target, so it is not held. Metadata and
    obfuscated internal spellings are denied wherever they appear.
    """
    worst: Optional[UriVerdict] = None
    for raw, keyed in iter_uri_candidates(arguments):
        v = classify(raw, lab_allow)
        if v.verdict == "deny":
            return v
        if v.verdict == "hold" and keyed and worst is None:
            worst = v
    return worst
