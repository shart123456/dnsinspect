import asyncio
import importlib.util
from pathlib import Path

import dns.exception
import dns.message
import pytest

_spec = importlib.util.spec_from_file_location("dnsinspect", Path(__file__).resolve().parent.parent / "dnsinspect.py")
di = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(di)


def test_spf_redirect_supplies_policy():
    assert di.parse_spf("v=spf1 redirect=_spf.example.com")["all"] == "from redirect=_spf.example.com"


def test_spf_all_qualifier():
    assert di.parse_spf("v=spf1 include:_spf.example.com -all")["all"] == "fail"
    assert di.parse_spf("v=spf1 ip4:192.0.2.1")["all"].startswith("missing")


@pytest.mark.parametrize("value", ["p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC", "k=rsa; p=MIGf", "v=DKIM1; k=rsa; p=abc"])
def test_dkim_detected_with_or_without_version(value):
    assert di.classify_txt(value)["format"] == "DKIM"


@pytest.mark.parametrize("value,fmt", [("v=DMARC1; p=none", "DMARC"), ("pardot123=abc", "key=value (unrecognised)")])
def test_not_mistaken_for_dkim(value, fmt):
    assert di.classify_txt(value)["format"] == fmt


def test_verification_tokens():
    assert di.classify_txt("google-site-verification=abc")["vendor"] == "google"
    assert di.classify_txt("MS=ms12345678")["vendor"] == "Microsoft 365"


@pytest.mark.parametrize("value,host", [("https://www.example.com/a/b", "www.example.com"), ("example.com:8443", "example.com"), ("192.0.2.1", "192.0.2.1")])
def test_host_from_input(value, host):
    assert di.host_from_input(value) == host


def test_host_from_input_rejects_garbage():
    with pytest.raises(SystemExit):
        di.host_from_input("not a host ::")


def _query():
    return dns.message.make_query("example.com", "A")


def test_send_retries_timeout_then_succeeds(monkeypatch):
    calls = {"n": 0}
    response = dns.message.make_response(_query())

    async def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise dns.exception.Timeout
        return response

    monkeypatch.setattr(di.dns.asyncquery, "tcp", flaky)
    r = asyncio.run(di.send("tcp", _query(), "127.0.0.1", 53, 0.1, asyncio.Semaphore(2), 1))
    assert "error" not in r and r["attempts"] == 2


@pytest.mark.parametrize("retries,expected", [(1, "timeout after 0.1s (2 tries)"), (0, "timeout after 0.1s")])
def test_send_reports_timeouts(monkeypatch, retries, expected):
    async def dead(*a, **k):
        raise dns.exception.Timeout

    monkeypatch.setattr(di.dns.asyncquery, "tcp", dead)
    r = asyncio.run(di.send("tcp", _query(), "127.0.0.1", 53, 0.1, asyncio.Semaphore(2), retries))
    assert r["error"] == expected


def test_failed_transport_is_not_a_miss():
    udp = {"answer": [{"name": "a.", "type": "A", "text": "192.0.2.1"}]}
    tcp = {"error": "timeout"}
    cmp = di.compare(udp, tcp)
    assert cmp["missing_over_udp"] == [] and cmp["failed"] == ["tcp"]
    assert di.seen_over({"udp": udp, "tcp": tcp}) == {("a.", "A", "192.0.2.1"): "UDP (TCP failed)"}


def test_truncated_udp_counts_as_missed():
    udp = {"answer": []}
    tcp = {"answer": [{"name": "a.", "type": "TXT", "text": '"x"'}]}
    assert di.compare(udp, tcp)["missing_over_udp"] == [("a.", "TXT", '"x"')]
