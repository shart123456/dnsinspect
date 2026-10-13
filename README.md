# dnsinspect

Query a host over **UDP and TCP** and show every DNS record in full.

Many DNS clients only use UDP. When an answer is too large for a UDP packet, the server sets the truncation (TC) bit and the client is meant to retry over TCP. Clients that skip that retry silently get zero records. Large TXT sets on corporate domains are where this happens most: dozens of SPF, DMARC and domain-verification records. `dnsinspect` sends every query over both transports to the same resolver and shows what each one returned, so you can see exactly what a UDP-only tool misses.

## Features

- Every record type is queried over UDP and TCP, with each transport's rcode, flags, size, latency and truncation, plus the records UDP missed.
- Every rdata field is broken out for each record in the answer, authority and additional sections.
- TXT records are split into their individual strings and parsed when they are a known format:
  - SPF, legacy SPF2.0 (Sender ID), DMARC, DKIM (with or without `v=DKIM1`)
  - MTA-STS, TLS-RPT, BIMI, MCP registry keys
  - vendor domain-verification tokens
- Accepts URLs, `host:port`, bare hostnames or IPs. IPs get a PTR lookup.
- Reads a list of domains from a file. All queries run concurrently with asyncio, capped by `--concurrency`, and output stays in input order.
- Retries a timed-out query, and labels a record "TCP failed" rather than "UDP only" when one transport never answered.
- Text, table (`--table`) or JSON (`--json`) output.

## Install and run

The script is a single file with inline dependency metadata ([PEP 723](https://peps.python.org/pep-0723/)), so [uv](https://docs.astral.sh/uv/) installs `dnspython` on first run:

```bash
uv run dnsinspect.py example.com
./dnsinspect.py example.com          # same thing, via the uv shebang
```

Without uv: `pip install "dnspython>=2.6,<3"`, then `python dnsinspect.py example.com`. It needs Python 3.10 or later.

## Usage

```bash
uv run dnsinspect.py https://www.example.com/some/path           # URL, host:port or bare host
uv run dnsinspect.py example.com --types TXT MX --server 1.1.1.1
uv run dnsinspect.py example.com --related                       # also _dmarc, _mta-sts, _smtp._tls, default._bimi
uv run dnsinspect.py example.com --udp-size 0                    # plain 512-byte UDP, no EDNS
uv run dnsinspect.py example.com --json > out.json
uv run dnsinspect.py -f domains.txt --table                      # one per line, # comments allowed
uv run dnsinspect.py -f domains.txt --table --server 1.1.1.1 --concurrency 20
```

| Option | Default | Meaning |
|---|---|---|
| `targets` | | URLs, hostnames or IP addresses |
| `-f, --file` | | File with one URL/hostname/IP per line (`#` comments allowed, duplicates removed) |
| `--types` | `A AAAA CNAME MX NS SOA TXT CAA HTTPS SRV` | Record types to query |
| `--server` | first system resolver | Resolver IP |
| `--port` | `53` | Resolver port |
| `--timeout` | `5.0` | Seconds per attempt |
| `--retries` | `1` | Extra attempts after a timeout, per transport |
| `--concurrency` | `50` | Maximum queries in flight at once |
| `--udp-size` | `1232` | EDNS UDP payload size; `0` disables EDNS (512 bytes) |
| `--dnssec` | off | Set the DO bit to request RRSIGs |
| `--related` | off | Also query the mail-policy names (`_dmarc`, `_mta-sts`, `_smtp._tls`, `default._bimi`) |
| `--all-sections` | off | Also show the authority and additional sections |
| `--table` | off | Transport table plus records table, and a per-domain summary for lists |
| `--json` | off | Full structured results (a list when there are several hosts) |
| `--width` | terminal width, or 160 when piped | Table width |

### Example

```
$ uv run dnsinspect.py example.com --types A TXT --server 1.1.1.1 --table
example.com  via 1.1.1.1:53  UDP EDNS 1232
┌─────────────┬──────┬───────────┬───────────┬───────────┬──────────┬───────────┬───────────┬──────────┬───────────────┐
│ Query       │ Type │ UDP rcode │ Truncated │ UDP bytes │ UDP recs │ TCP rcode │ TCP bytes │ TCP recs │ Missed by UDP │
├─────────────┼──────┼───────────┼───────────┼───────────┼──────────┼───────────┼───────────┼──────────┼───────────────┤
│ example.com │ A    │ NOERROR   │ no        │ 72        │ 2        │ NOERROR   │ 72        │ 2        │ 0             │
├─────────────┼──────┼───────────┼───────────┼───────────┼──────────┼───────────┼───────────┼──────────┼───────────────┤
│ example.com │ TXT  │ NOERROR   │ no        │ 109       │ 2        │ NOERROR   │ 109       │ 2        │ 0             │
└─────────────┴──────┴───────────┴───────────┴───────────┴──────────┴───────────┴───────────┴──────────┴───────────────┘

┌───────┬──────────────┬──────┬─────┬──────────────────────────────────┬───────────────┬───────────┐
│ Query │ Name         │ Type │ TTL │ Value                            │ Details       │ Seen over │
├───────┼──────────────┼──────┼─────┼──────────────────────────────────┼───────────────┼───────────┤
│ A     │ example.com. │ A    │ 43  │ 172.66.147.243                   │               │ both      │
├───────┼──────────────┼──────┼─────┼──────────────────────────────────┼───────────────┼───────────┤
│ A     │ example.com. │ A    │ 43  │ 104.20.23.154                    │               │ both      │
├───────┼──────────────┼──────┼─────┼──────────────────────────────────┼───────────────┼───────────┤
│ TXT   │ example.com. │ TXT  │ 110 │ v=spf1 -all                      │ SPF; all=fail │ both      │
├───────┼──────────────┼──────┼─────┼──────────────────────────────────┼───────────────┼───────────┤
│ TXT   │ example.com. │ TXT  │ 110 │ _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9 │ opaque string │ both      │
└───────┴──────────────┴──────┴─────┴──────────────────────────────────┴───────────────┴───────────┘
```

On a domain with a large TXT set, the `Truncated` column shows `yes`, `UDP recs` is 0, and every TXT record is marked `TCP only`.

### Reading "Seen over"

| Value | Meaning |
|---|---|
| `both` | Returned over UDP and TCP |
| `TCP only` | Missing from the UDP answer, usually because UDP was truncated |
| `UDP only` | Missing from the TCP answer, usually because CDN or round-robin records rotate between queries |
| `UDP (TCP failed)` / `TCP (UDP failed)` | The other transport errored or timed out, so there is nothing to compare |

## Tips for large lists

- Use a public resolver (`--server 1.1.1.1` or `8.8.8.8`). Home routers and small forwarders often can't handle dozens of concurrent TCP connections, and their TCP timeouts look like missing records.
- Lower `--concurrency` if you see timeouts, or raise `--retries`.
- Add `--related` to check DMARC, MTA-STS, TLS-RPT and BIMI for every domain.

## Tests

```bash
uv run --with "dnspython>=2.6,<3" --with pytest python -m pytest -q tests
```

The tests make no network calls; the DNS transport is mocked.
