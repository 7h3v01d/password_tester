# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
import hashlib
import json

import pytest

from password_tester import hibp


def test_message_for_single_hit_is_grammatical():
    assert "1 times" not in hibp.pwned_message(1)


def test_clean_rejects_non_list_response():
    with pytest.raises(ValueError):
        hibp.clean_breaches({"error": "cloudflare"})


def test_clean_normalises_hostile_entries():
    out = hibp.clean_breaches([1, None, {"Title": None, "PwnCount": "9", "DataClasses": "Passwords",
                                         "IsVerified": "no", "_text": "junk"}])
    assert len(out) == 1
    b = out[0]
    assert b["Title"] == "" and b["PwnCount"] == 0 and b["DataClasses"] == []
    assert "IsVerified" not in b and "_text" not in b
    hibp.prep(out)


def test_count_in_range_ignores_padding():
    body = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\nABCDEF0000000000000000000000000000:0\r\n"
    assert hibp.count_in_range(body, "0018a45c4d1def81644b54ab7f969b88d65") == 3
    assert hibp.count_in_range(body, "ABCDEF0000000000000000000000000000") == 0


def test_password_check_sends_only_prefix_with_padding(monkeypatch):
    seen = {}

    def fake(url, headers=None, timeout=30):
        seen["url"], seen["headers"] = url, headers or {}
        return b""
    monkeypatch.setattr(hibp, "_fetch", fake)
    hibp.pwned_count("correct horse battery staple")
    digest = hashlib.sha1(b"correct horse battery staple").hexdigest().upper()
    assert seen["url"] == hibp.RANGE_API + digest[:5]
    assert seen["headers"].get("Add-Padding") == "true"


def test_requests_use_certifi_aware_context(monkeypatch):
    kw = {}

    class R:
        def __enter__(s): return s
        def __exit__(s, *a): pass
        def read(s, *a): return b"[]"
    monkeypatch.setattr(hibp.urllib.request, "urlopen", lambda req, **k: (kw.update(k), R())[1])
    hibp.hibp_get("breaches")
    assert kw.get("context") is hibp.SSL_CTX


@pytest.mark.parametrize("blob", [{"fetched": "yesterday", "data": []}, {"fetched": 1, "data": [{"Title": None}]},
                                  {"fetched": 1, "data": [1, 2]}, [1, 2]])
def test_corrupt_cache_only_raises_expected(tmp_path, blob):
    p = tmp_path / "c.json"
    p.write_text(json.dumps(blob))
    try:
        hibp.prep(hibp.load_cache_blob(str(p))[1])
    except (OSError, ValueError):
        pass


def test_cache_stores_raw_only(tmp_path):
    p = str(tmp_path / "sub" / "c.json")
    raw = hibp.clean_breaches([{"Title": "A", "Description": "<b>x</b>"}])
    hibp.prep(raw)
    assert hibp.save_cache(p, raw)
    assert not any(k.startswith("_") for k in json.load(open(p))["data"][0])
