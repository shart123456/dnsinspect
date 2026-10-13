#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["dnspython>=2.6,<3"]
# ///
"""dnsinspect: query a host over UDP and TCP and show every DNS record in full.

Usage:
    uv run dnsinspect.py https://www.example.com/some/path
    uv run dnsinspect.py example.com --types TXT MX --server 1.1.1.1
    uv run dnsinspect.py example.com --related          # also _dmarc, _mta-sts, ...
    uv run dnsinspect.py example.com --udp-size 0       # plain 512-byte UDP, no EDNS
    uv run dnsinspect.py example.com --json > out.json
    uv run dnsinspect.py -f domains.txt --table         # one per line, # comments ok
    uv run dnsinspect.py -f domains.txt --concurrency 100

For every record type it sends the same query twice, once over UDP and once
over TCP, to the same resolver. It reports the header flags, size, latency and
truncation of each response, every record in the answer/authority/additional
sections with each rdata field broken out, and the records UDP missed.
All queries (every type, both transports, every domain) run concurrently,
capped by --concurrency; output still comes out in input order.
TXT records are also split into their individual strings and parsed when
they are a known format (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, MCP,
domain-verification tokens).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import shutil
import sys
import textwrap
import time
from urllib.parse import urlsplit

import dns.asyncquery
import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename

DEFAULT_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA", "HTTPS", "SRV"]
RELATED_PREFIXES = ["_dmarc", "_mta-sts", "_smtp._tls", "default._bimi", "_domainkey"]

USE_COLOR = sys.stdout.isatty()
HOSTNAME_RE = re.compile(r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*")


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def bold(t):
    return c(t, "1")


def dim(t):
    return c(t, "2")


def red(t):
    return c(t, "31")


def green(t):
    return c(t, "32")


def yellow(t):
    return c(t, "33")


def cyan(t):
    return c(t, "36")


# ---------------------------------------------------------------- input


def host_from_input(value: str) -> str:
    """Accept a URL, host:port, bare hostname or IP and return the host."""
    value = value.strip()
    if "://" not in value:
        value = "//" + value
    try:
        host = urlsplit(value).hostname
    except ValueError:
        host = None
    host = (host or "").rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not HOSTNAME_RE.fullmatch(host):
        raise SystemExit(f"not a valid hostname, URL or IP: {value.lstrip('/')!r}")
    return host


def default_server() -> str:
    try:
        return dns.resolver.Resolver().nameservers[0]
    except Exception:
        return "1.1.1.1"


# ---------------------------------------------------------------- querying


def make_query(qname: str, rdtype: str, udp_size: int, dnssec: bool) -> dns.message.Message:
    if udp_size > 0:
        return dns.message.make_query(qname, rdtype, use_edns=0, payload=udp_size, want_dnssec=dnssec)
    return dns.message.make_query(qname, rdtype, use_edns=False)


async def send(transport: str, query: dns.message.Message, server: str, port: int, timeout: float, limit: asyncio.Semaphore, retries: int = 1) -> dict:
    """Send one query, retrying timeouts; return the response plus transport metadata (never raises)."""
    result = {"transport": transport, "server": f"{server}:{port}"}
    for attempt in range(retries + 1):
        async with limit:
            start = time.perf_counter()
            try:
                if transport == "udp":
                    # keep the truncated answer instead of raising, so we can show what UDP actually delivered
                    response = await dns.asyncquery.udp(query, server, port=port, timeout=timeout, raise_on_truncation=False)
                else:
                    response = await dns.asyncquery.tcp(query, server, port=port, timeout=timeout)
                break
            except dns.exception.Timeout:
                result["error"] = f"timeout after {timeout}s" + (f" ({attempt + 1} tries)" if attempt else "")
            except Exception as e:  # network errors, refused TCP, malformed response: not worth retrying
                result["error"] = f"{type(e).__name__}: {e}"
                return result
        if attempt < retries:
            await asyncio.sleep(0.5 * (attempt + 1))  # back off so a struggling resolver can drain
    else:
        return result
    result.pop("error", None)
    if attempt:
        result["attempts"] = attempt + 1
    result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
    result["response"] = response
    result["size_bytes"] = len(response.to_wire())
    return result


# ---------------------------------------------------------------- parsing rdata


def rdata_fields(rdata) -> dict:
    """Every field of an rdata object, as JSON-friendly values."""
    fields = {}
    for slot in _all_slots(type(rdata)):
        if slot in ("rdclass", "rdtype", "rdcomment") or slot.startswith("_"):
            continue
        value = getattr(rdata, slot, None)
        fields[slot] = _jsonable(value)
    return fields


def _all_slots(cls):
    seen = []
    for klass in reversed(cls.__mro__):
        for s in getattr(klass, "__slots__", ()):
            if s not in seen:
                seen.append(s)
    return seen


def _jsonable(value):
    if isinstance(value, bytes):
        try:
            return value.decode()
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, dns.name.Name):
        return value.to_text()
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    to_text = getattr(value, "to_text", None)
    return to_text() if callable(to_text) else str(value)


# ---------------------------------------------------------------- TXT analysis

SPF_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


def parse_spf(text: str) -> dict:
    terms = []
    all_policy = None
    for token in text.split()[1:]:
        qualifier = "+"
        if token[0] in SPF_QUALIFIERS:
            qualifier, token = token[0], token[1:]
        if "=" in token and ":" not in token.split("=")[0]:
            name, _, value = token.partition("=")
            terms.append({"kind": "modifier", "name": name, "value": value})
            continue
        name, _, value = token.partition(":")
        if "/" in name and not value:  # e.g. "a/24"
            name, _, value = name.partition("/")
            value = "/" + value
        entry = {"kind": "mechanism", "qualifier": SPF_QUALIFIERS[qualifier], "name": name.lower(), "value": value}
        if "%{" in value:
            entry["macro"] = True
        if name.lower() == "all":
            all_policy = SPF_QUALIFIERS[qualifier]
        terms.append(entry)
    lookups = sum(1 for t in terms if t.get("name") in ("include", "a", "mx", "ptr", "exists", "redirect"))
    redirect = next((t["value"] for t in terms if t["kind"] == "modifier" and t["name"].lower() == "redirect"), None)
    if all_policy:
        policy = all_policy
    elif redirect:
        # RFC 7208 6.1: with no "all", the redirect target's record decides the result
        policy = f"from redirect={redirect}"
    else:
        policy = "missing (no all mechanism, defaults to neutral)"
    return {
        "format": "SPF",
        "all": policy,
        "dns_lookup_terms": lookups,
        "over_10_lookup_limit_at_top_level": lookups > 10,
        "terms": terms,
    }


def parse_tags(text: str, fmt: str) -> dict:
    tags = {}
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip()] = value.strip()
    out = {"format": fmt, "tags": tags}
    if fmt == "DMARC":
        mailboxes = []
        for key in ("rua", "ruf"):
            for uri in tags.get(key, "").split(","):
                uri = uri.strip()
                if uri:
                    mailboxes.append({"tag": key, "uri": uri})
        out["report_destinations"] = mailboxes
    return out


VERIFICATION_RE = re.compile(
    r"^(?P<vendor>[A-Za-z0-9_.-]+?)[-_](?:domain[-_])?(?:site[-_])?(?:verification|verify|verification-code|domain-verification)(?:-[a-z0-9]+)?[=:]",
    re.I,
)


def classify_txt(text: str) -> dict:
    low = text.lower()
    if low.startswith("v=spf1"):
        return parse_spf(text)
    if low.startswith("spf2.0/"):
        return {"format": "Sender ID (legacy SPF2.0)", "scope": text.split()[0].split("/", 1)[1], "body": text}
    if low.startswith("v=dmarc1"):
        return parse_tags(text, "DMARC")
    # v=DKIM1 is optional (RFC 6376 3.6.1), so also accept a key record that opens with k=/p=/h=/t= and carries p=
    if low.startswith("v=dkim1") or (re.match(r"^(k|p|h|t)=", low) and re.search(r"(^|;)\s*p=", low)):
        return parse_tags(text, "DKIM")
    if low.startswith("v=stsv1"):
        return parse_tags(text, "MTA-STS")
    if low.startswith("v=tlsrptv1"):
        return parse_tags(text, "TLS-RPT")
    if low.startswith("v=bimi1"):
        return parse_tags(text, "BIMI")
    if low.startswith("v=mcpv1"):
        return parse_tags(text, "MCP Registry server key")
    if re.match(r"^ms=", low):
        return {"format": "Domain verification", "vendor": "Microsoft 365"}
    if re.match(r"^00d[a-z0-9]{12}=", low):
        return {"format": "Domain verification", "vendor": "Salesforce (org id)"}
    match = VERIFICATION_RE.match(text) or re.match(r"^(?P<vendor>[A-Za-z0-9]+)_verify_", text)
    if match:
        return {"format": "Domain verification", "vendor": match.group("vendor")}
    if "=" in text:
        return {"format": "key=value (unrecognised)", "key": text.split("=", 1)[0]}
    return {"format": "opaque string"}


def txt_details(rdata) -> dict:
    segments = [s.decode(errors="replace") for s in rdata.strings]
    joined = "".join(segments)
    return {
        "string_count": len(segments),
        "segment_lengths": [len(s) for s in rdata.strings],
        "joined_length": len(joined),
        "joined": joined,
        "segments": segments if len(segments) > 1 else None,
        "parsed": classify_txt(joined),
    }


# ---------------------------------------------------------------- building results


def section_records(section) -> list[dict]:
    records = []
    for rrset in section:
        for rdata in rrset:
            rec = {
                "name": rrset.name.to_text(),
                "ttl": rrset.ttl,
                "class": dns.rdataclass.to_text(rrset.rdclass),
                "type": dns.rdatatype.to_text(rrset.rdtype),
                "text": rdata.to_text(),
                "fields": rdata_fields(rdata),
            }
            if rrset.rdtype == dns.rdatatype.TXT:
                rec["txt"] = txt_details(rdata)
            records.append(rec)
    return records


def describe(result: dict) -> dict:
    out = {k: v for k, v in result.items() if k != "response"}
    response = result.get("response")
    if response is None:
        return out
    out["rcode"] = dns.rcode.to_text(response.rcode())
    out["flags"] = dns.flags.to_text(response.flags).split()
    out["truncated"] = bool(response.flags & dns.flags.TC)
    out["edns"] = (
        {"version": response.edns, "payload": response.payload, "options": [str(o) for o in response.options]}
        if response.edns >= 0
        else None
    )
    out["answer"] = section_records(response.answer)
    out["authority"] = section_records(response.authority)
    out["additional"] = section_records(response.additional)
    return out


def compare(udp: dict, tcp: dict) -> dict:
    def keyset(d):
        return {(r["name"], r["type"], r["text"]) for r in d.get("answer", [])}

    u, t = keyset(udp), keyset(tcp)
    if "error" in udp or "error" in tcp:
        # one side never answered, so a difference says nothing about what that transport can carry
        failed = [n for n, d in (("udp", udp), ("tcp", tcp)) if "error" in d]
        return {"udp_answers": len(u), "tcp_answers": len(t), "missing_over_udp": [], "only_over_udp": [], "identical": None, "failed": failed}
    return {
        "udp_answers": len(u),
        "tcp_answers": len(t),
        "missing_over_udp": sorted(t - u),
        "only_over_udp": sorted(u - t),
        "identical": u == t,
    }


async def inspect(qname: str, rdtype: str, args, limit: asyncio.Semaphore) -> dict:
    query = make_query(qname, rdtype, args.udp_size, args.dnssec)
    udp, tcp = await asyncio.gather(
        send("udp", query, args.server, args.port, args.timeout, limit, args.retries),
        send("tcp", query, args.server, args.port, args.timeout, limit, args.retries),
    )
    udp, tcp = describe(udp), describe(tcp)
    return {"qname": qname, "rdtype": rdtype, "udp": udp, "tcp": tcp, "comparison": compare(udp, tcp)}


# ---------------------------------------------------------------- text output


def print_transport(label: str, d: dict):
    if "error" in d:
        print(f"  {label:<4} {red('ERROR')} {d['error']}")
        return
    trunc = red("TRUNCATED") if d["truncated"] else green("complete")
    edns = f"edns payload {d['edns']['payload']}" if d["edns"] else "no EDNS"
    rcode = d["rcode"] if d["rcode"] == "NOERROR" else yellow(d["rcode"])
    print(
        f"  {label:<4} {rcode:<8} {trunc:<10} {len(d['answer']):>3} answers  "
        f"{d['size_bytes']:>5} bytes  {d['latency_ms']:>7} ms  flags {' '.join(d['flags'])}  {dim(edns)}"
    )


def print_record(rec: dict, indent="    "):
    head = f"{indent}{cyan(rec['type']):<6} {rec['name']}  ttl={rec['ttl']}"
    print(head)
    if "txt" in rec:
        t = rec["txt"]
        print(f"{indent}  value     {t['joined']}")
        print(f"{indent}  strings   {t['string_count']} (lengths {t['segment_lengths']}, joined {t['joined_length']} chars)")
        parsed = t["parsed"]
        print(f"{indent}  format    {bold(parsed['format'])}")
        for key, value in parsed.items():
            if key in ("format", "terms", "tags", "report_destinations"):
                continue
            print(f"{indent}  {key:<9} {value}")
        for term in parsed.get("terms", []):
            if term["kind"] == "mechanism":
                flag = yellow(" (macro)") if term.get("macro") else ""
                print(f"{indent}    {term['qualifier']:<8} {term['name']:<8} {term['value']}{flag}")
            else:
                print(f"{indent}    modifier {term['name']:<8} {term['value']}")
        for key, value in parsed.get("tags", {}).items():
            print(f"{indent}    {key:<8} {value}")
        for dest in parsed.get("report_destinations", []):
            print(f"{indent}    report   {dest['tag']} -> {dest['uri']}")
        return
    for key, value in rec["fields"].items():
        print(f"{indent}  {key:<10} {value}")


def print_result(r: dict, show_extra: bool):
    print(bold(f"\n{r['rdtype']} {r['qname']}"))
    print_transport("UDP", r["udp"])
    print_transport("TCP", r["tcp"])
    cmp = r["comparison"]
    if cmp.get("failed"):
        print(yellow(f"  {'/'.join(cmp['failed']).upper()} failed, so UDP and TCP cannot be compared for this query"))
    elif cmp["missing_over_udp"]:
        print(red(f"  UDP missed {len(cmp['missing_over_udp'])} of {cmp['tcp_answers']} records that TCP returned"))
    elif not cmp["identical"]:
        print(yellow("  UDP and TCP answers differ (records may rotate between queries)"))
    best = r["tcp"] if "error" not in r["tcp"] else r["udp"]
    if "error" in best:
        return
    if not best["answer"]:
        print(dim("  no records"))
    for rec in best["answer"]:
        print_record(rec)
    if show_extra:
        for section in ("authority", "additional"):
            if best[section]:
                print(dim(f"  -- {section} --"))
                for rec in best[section]:
                    print_record(rec)


# ---------------------------------------------------------------- table output

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def render_table(headers: list[str], rows: list[list[str]], width: int, wrap_cols: tuple[int, ...]) -> str:
    """Box-drawn table; columns in wrap_cols shrink and wrap so the table fits `width`."""
    plain = lambda s: ANSI_RE.sub("", str(s))  # noqa: E731
    cols = len(headers)
    natural = [max([len(plain(h)) for h in [headers[i]]] + [len(plain(line)) for r in rows for line in str(r[i]).splitlines() or [""]]) for i in range(cols)]
    widths = natural[:]
    overhead = 3 * cols + 1
    excess = sum(widths) + overhead - width
    # take space from the widest wrappable column first, never below 12 chars
    while excess > 0:
        candidates = [i for i in wrap_cols if widths[i] > 12]
        if not candidates:
            break
        i = max(candidates, key=lambda j: widths[j])
        cut = min(excess, widths[i] - 12, max(1, widths[i] - max(widths[j] for j in candidates if j != i) if len(candidates) > 1 else excess))
        widths[i] -= cut
        excess -= cut

    def wrap(text: str, w: int) -> list[str]:
        lines = []
        for para in str(text).splitlines() or [""]:
            lines += textwrap.wrap(para, w, break_long_words=True, break_on_hyphens=False) or [""]
        return lines

    def line(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def row_lines(cells, color=None):
        wrapped = [wrap(plain(c_), widths[i]) if i in wrap_cols else str(c_).splitlines() or [""] for i, c_ in enumerate(cells)]
        height = max(len(w) for w in wrapped)
        out = []
        for n in range(height):
            parts = []
            for i, w in enumerate(wrapped):
                text = w[n] if n < len(w) else ""
                pad = " " * (widths[i] - len(plain(text)))
                parts.append(f" {color(text) if color else text}{pad} ")
            out.append("│" + "│".join(parts) + "│")
        return out

    out = [line("┌", "┬", "┐")]
    out += row_lines(headers, bold)
    out.append(line("├", "┼", "┤"))
    for idx, r in enumerate(rows):
        out += row_lines(r)
        out.append(line("├", "┼", "┤") if idx < len(rows) - 1 else line("└", "┴", "┘"))
    if not rows:
        out.append(line("└", "┴", "┘"))
    return "\n".join(out)


def summarise_record(rec: dict) -> str:
    """One-cell description of what a record means."""
    if "txt" in rec:
        p = rec["txt"]["parsed"]
        bits = [p["format"]]
        if p["format"] == "SPF":
            names = [t["name"] for t in p["terms"] if t["kind"] == "mechanism" and t["name"] != "all"]
            counts = ", ".join(f"{names.count(n)} {n}" for n in dict.fromkeys(names))
            bits.append(f"all={p['all']}")
            if counts:
                bits.append(counts)
            if any(t.get("macro") for t in p["terms"]):
                bits.append("uses macros")
        elif "vendor" in p:
            bits.append(f"vendor={p['vendor']}")
        elif "tags" in p:
            bits += [f"{k}={v}" for k, v in p["tags"].items() if k in ("p", "sp", "mode", "k", "l", "rua", "ruf")]
        if rec["txt"]["string_count"] > 1:
            bits.append(f"{rec['txt']['string_count']} strings")
        return "; ".join(bits)
    if len(rec["fields"]) == 1:  # A, AAAA, NS, CNAME, PTR: the value already says it all
        return ""
    return ", ".join(f"{k}={v}" for k, v in rec["fields"].items())


def seen_over(results: dict) -> dict:
    """Map (name, type, text) -> 'both' / 'TCP only' / 'UDP only' / 'UDP (TCP failed)' / 'TCP (UDP failed)'."""
    udp = {(r["name"], r["type"], r["text"]) for r in results["udp"].get("answer", [])}
    tcp = {(r["name"], r["type"], r["text"]) for r in results["tcp"].get("answer", [])}
    if "error" in results["tcp"]:
        return {k: "UDP (TCP failed)" for k in udp}
    if "error" in results["udp"]:
        return {k: "TCP (UDP failed)" for k in tcp}
    return {k: "both" if k in udp and k in tcp else ("TCP only" if k in tcp else "UDP only") for k in udp | tcp}


def print_tables(host: str, results: list[dict], args):
    width = args.width or (shutil.get_terminal_size((160, 40)).columns if sys.stdout.isatty() else 160)

    def cell(d, key):
        return d.get(key, "") if "error" not in d else ""

    transport_rows = []
    for r in results:
        u, t, cmp = r["udp"], r["tcp"], r["comparison"]
        missed = len(cmp["missing_over_udp"])
        transport_rows.append([
            r["qname"], r["rdtype"],
            u.get("error") or u["rcode"],
            red("yes") if u.get("truncated") else "no",
            cell(u, "size_bytes"), cmp["udp_answers"],
            t.get("error") or t["rcode"],
            cell(t, "size_bytes"), cmp["tcp_answers"],
            red(missed) if missed else "0",
        ])
    print(bold(f"{host}") + dim(f"  via {args.server}:{args.port}  UDP " + (f"EDNS {args.udp_size}" if args.udp_size else "no EDNS")))
    print(render_table(
        ["Query", "Type", "UDP rcode", "Truncated", "UDP bytes", "UDP recs", "TCP rcode", "TCP bytes", "TCP recs", "Missed by UDP"],
        transport_rows, width, wrap_cols=(0, 2, 6)))

    record_rows = []
    for r in results:
        seen = seen_over(r)
        merged = {}
        for d in (r["tcp"], r["udp"]):
            for rec in d.get("answer", []) + (d.get("authority", []) + d.get("additional", []) if args.all_sections else []):
                merged.setdefault((rec["name"], rec["type"], rec["text"]), rec)
        for key, rec in merged.items():
            value = rec["txt"]["joined"] if "txt" in rec else rec["text"]
            s = seen.get(key, "authority/additional")
            record_rows.append([r["rdtype"], rec["name"], rec["type"], rec["ttl"], value, summarise_record(rec), red(s) if s == "TCP only" else s])
    print()
    print(render_table(["Query", "Name", "Type", "TTL", "Value", "Details", "Seen over"], record_rows, width, wrap_cols=(1, 4, 5)))


# ---------------------------------------------------------------- main


def read_targets(args) -> list[str]:
    """Targets from the command line plus any --file, blank lines and # comments skipped, deduplicated."""
    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        targets.append(line)
        except OSError as e:
            raise SystemExit(f"cannot read {args.file}: {e}")
    if not targets:
        raise SystemExit("give a URL/hostname/IP, or a file of them with -f/--file")
    seen, unique = set(), []
    for t in targets:
        try:
            host = host_from_input(t)
        except SystemExit as e:
            print(yellow(f"skipping {t!r}: {e}"), file=sys.stderr)
            continue
        if host not in seen:
            seen.add(host)
            unique.append(host)
    return unique


async def run_host(host: str, args, limit: asyncio.Semaphore) -> list[dict]:
    queries = []
    try:
        ipaddress.ip_address(host)
        queries.append((dns.reversename.from_address(host).to_text(), "PTR"))
    except ValueError:
        types = [t.upper() for t in (args.types or DEFAULT_TYPES)]
        queries += [(host, t) for t in types]
        if args.related:
            queries += [(f"{p}.{host}", "TXT") for p in RELATED_PREFIXES if p != "_domainkey"]
    return list(await asyncio.gather(*(inspect(q, t, args, limit) for q, t in queries)))


def print_text(host: str, results: list[dict], args):
    edns = f"EDNS {args.udp_size}" if args.udp_size else "no EDNS"
    print(bold(f"{host}") + dim(f"  via {args.server}:{args.port}  UDP {edns}"))
    for r in results:
        print_result(r, args.all_sections)

    truncated = [r for r in results if r["udp"].get("truncated")]
    missed = sum(len(r["comparison"]["missing_over_udp"]) for r in results)
    print(bold("\nSummary"))
    print(f"  {len(results)} queries, {len(truncated)} truncated over UDP, {missed} records only visible over TCP")
    for r in truncated:
        print(f"    {r['rdtype']} {r['qname']}: UDP {r['comparison']['udp_answers']} / TCP {r['comparison']['tcp_answers']}")


def print_overall(all_results: dict[str, list[dict]], args):
    """One row per domain, printed after every domain when more than one was given."""
    width = args.width or (shutil.get_terminal_size((160, 40)).columns if sys.stdout.isatty() else 160)
    rows = []
    for host, results in all_results.items():
        truncated = [r["rdtype"] if r["qname"].rstrip(".") == host else f"{r['rdtype']} {r['qname']}" for r in results if r["udp"].get("truncated")]
        errors = sum(1 for r in results for t in ("udp", "tcp") if "error" in r[t])
        udp = sum(r["comparison"]["udp_answers"] for r in results)
        tcp = sum(r["comparison"]["tcp_answers"] for r in results)
        missed = sum(len(r["comparison"]["missing_over_udp"]) for r in results)
        rows.append([host, len(results), udp, tcp, red(missed) if missed else "0", ", ".join(truncated) or "-", errors or "0"])
    print(bold(f"\n\nAll domains ({len(rows)})"))
    print(render_table(["Domain", "Queries", "UDP recs", "TCP recs", "Missed by UDP", "Truncated over UDP", "Errors"], rows, width, wrap_cols=(0, 5)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="URLs, hostnames or IP addresses")
    ap.add_argument("-f", "--file", help="text file with one URL/hostname/IP per line (# comments allowed)")
    ap.add_argument("--types", nargs="+", default=None, help=f"record types (default: {' '.join(DEFAULT_TYPES)})")
    ap.add_argument("--server", default=None, help="resolver IP (default: first system resolver)")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--udp-size", type=int, default=1232, help="EDNS UDP payload size; 0 = no EDNS (512 bytes)")
    ap.add_argument("--dnssec", action="store_true", help="set the DO bit to request RRSIGs")
    ap.add_argument("--related", action="store_true", help="also query _dmarc, _mta-sts, _smtp._tls, default._bimi")
    ap.add_argument("--all-sections", action="store_true", help="also print authority and additional sections")
    ap.add_argument("--json", action="store_true", help="print full results as JSON")
    ap.add_argument("--table", action="store_true", help="print a transport table and a records table")
    ap.add_argument("--width", type=int, default=None, help="table width (default: terminal width, or 160 when piped)")
    ap.add_argument("--retries", type=int, default=1, help="extra attempts after a timeout, per transport (default: 1)")
    ap.add_argument("--concurrency", type=int, default=50, help="maximum queries in flight at once (default: 50)")
    args = ap.parse_args()
    args.server = args.server or default_server()
    if args.concurrency < 1:
        raise SystemExit("--concurrency must be at least 1")
    asyncio.run(amain(args, read_targets(args)))


async def amain(args, hosts: list[str]):
    limit = asyncio.Semaphore(args.concurrency)
    done = 0

    def progress(task, host):
        nonlocal done
        done += 1
        if len(hosts) > 1:
            print(dim(f"[{done}/{len(hosts)}] {host}"), file=sys.stderr)

    # start every domain at once; the semaphore caps how many queries are on the wire
    tasks = []
    for host in hosts:
        task = asyncio.create_task(run_host(host, args, limit))
        task.add_done_callback(lambda t, h=host: progress(t, h))
        tasks.append(task)

    all_results = {}
    # print in input order: each domain is printed as soon as it and every domain before it have finished
    for n, (host, task) in enumerate(zip(hosts, tasks), 1):
        results = await task
        all_results[host] = results
        if args.json:
            continue
        if n > 1:
            print("\n" + "=" * 80 + "\n")
        if args.table:
            print_tables(host, results, args)
        else:
            print_text(host, results, args)

    if args.json:
        doc = [{"host": h, "server": args.server, "results": r} for h, r in all_results.items()]
        print(json.dumps(doc[0] if len(doc) == 1 else doc, indent=2))
        return
    if len(hosts) > 1:
        print_overall(all_results, args)


if __name__ == "__main__":
    main()
