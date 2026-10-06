# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Have I Been Pwned: password range check, breach catalogue, email lookup, on-disk cache.

Breach data: Have I Been Pwned, https://haveibeenpwned.com (CC BY 4.0)
"""
import hashlib
import html
import json
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

API = "https://haveibeenpwned.com/api/v3/"
RANGE_API = "https://api.pwnedpasswords.com/range/"
UA = f"PasswordTesterApp/{__version__} (personal desktop tool)"
MAX_BODY = 32 * 1024 * 1024
DEMO_EMAIL = "multiple-breaches@hibp-integration-tests.com"
DEMO_KEY = "0" * 32

FLAG_NOTES = {
    "unverified": "Unverified: may not have been hacked from this site.",
    "fabricated": "Fabricated: probably not from this site, though the emails are real.",
    "sensitive": "Sensitive: addresses are hidden from public lookups.",
    "spam list": "Spam list: not a security hack, just a marketing/spam database.",
    "malware": "Malware: data harvested from infected machines.",
    "stealer logs": "Stealer logs: credentials captured by info-stealing malware.",
}


class BadResponse(ValueError):
    """Data from HIBP (or the on-disk cache) isn't the shape we expect."""


def cache_path():
    base = (os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
            or os.path.join(os.path.expanduser("~"), ".cache"))
    return os.path.join(base, "PasswordTester", "breaches_cache.json")


# ------------------------------------------------------------------ network
def _ssl_context():
    ctx = ssl.create_default_context()           # system store (keeps corporate/AV roots working)
    try:
        import certifi                           # optional: fixes stock macOS Python installs
        ctx.load_verify_locations(certifi.where())
    except (ImportError, OSError, ssl.SSLError):
        pass
    return ctx


SSL_CTX = _ssl_context()


def _fetch(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
        body = resp.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise BadResponse("response too large")
    return body


def hibp_get(path, key=None, timeout=30):
    headers = {"hibp-api-key": key} if key else None
    return json.loads(_fetch(API + path, headers, timeout).decode("utf-8"))


def count_in_range(body, suffix):
    """Find SUFFIX:COUNT in a Pwned Passwords range response. Padding rows have count 0."""
    suffix = suffix.upper()
    for line in body.splitlines():
        s, _, n = line.strip().partition(":")
        if s.upper() == suffix:
            return int(n) if n.strip().isdigit() else 0
    return 0


def pwned_count(password, timeout=15):
    """k-anonymity lookup: only the first 5 hex chars of the SHA-1 are sent; response is padded."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    body = _fetch(RANGE_API + digest[:5], {"Add-Padding": "true"}, timeout)
    return count_in_range(body.decode("utf-8", "replace"), digest[5:])


def breached_account_path(email):
    return "breachedaccount/" + urllib.parse.quote(email, safe="") + "?truncateResponse=false"


def explain_error(e):
    if isinstance(e, urllib.error.HTTPError):
        retry = e.headers.get("retry-after", "a few") if e.headers else "a few"
        return {401: "API key rejected (HIBP keys are 32 hex characters).",
                403: "Request refused (missing user agent, or your plan doesn't cover this).",
                404: "Not found.", 429: f"Rate limited. Try again in {retry} s.",
                503: "HIBP is temporarily unavailable (often a Cloudflare challenge).",
                }.get(e.code, f"Server replied HTTP {e.code}.")
    if isinstance(e, ValueError):                # BadResponse, JSONDecodeError, UnicodeDecodeError
        return "HIBP sent an unexpected response (often a Cloudflare challenge page). Try again shortly."
    reason = getattr(e, "reason", e)
    if isinstance(reason, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
        return ("SSL certificate check failed. On macOS run 'Install Certificates.command' in your "
                "Python folder (or pip install certifi). Otherwise a proxy/antivirus may be intercepting HTTPS.")
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "Timed out. Check your connection or firewall."
    if isinstance(reason, socket.gaierror):
        return "Couldn't resolve the server name. Are you offline?"
    return f"Network problem: {reason}"


def tier(n):
    if n >= 100_000:
        return "extremely common"
    if n >= 1_000:
        return "very common"
    if n >= 10:
        return "seen repeatedly"
    return "seen a handful of times"


def pwned_message(n):
    if n == 1:
        return "⚠ Appears once in leaked password data. Don't use it."
    return f"⚠ Appears {n:,} times in leaked password data ({tier(n)}). Don't use it."


# ------------------------------------------------------------------ catalogue data
_STR_FIELDS = ("Name", "Title", "Domain", "BreachDate", "AddedDate", "ModifiedDate", "Description")
_BOOL_FIELDS = ("IsVerified", "IsFabricated", "IsSensitive", "IsRetired", "IsSpamList", "IsMalware",
                "IsStealerLog", "IsSubscriptionFree")


def clean_breaches(data):
    """Validate/normalise a breach list from HIBP or the cache. Raises BadResponse if it isn't a list."""
    if not isinstance(data, list):
        raise BadResponse("expected a list of breaches")
    out = []
    for b in data:
        if not isinstance(b, dict):
            continue
        c = {k: v for k, v in b.items() if not k.startswith("_")}   # drop derived keys (old caches)
        for k in _STR_FIELDS:
            c[k] = c[k] if isinstance(c.get(k), str) else ""
        dc = c.get("DataClasses")
        c["DataClasses"] = [x for x in dc if isinstance(x, str)] if isinstance(dc, list) else []
        pc = c.get("PwnCount")
        c["PwnCount"] = pc if isinstance(pc, int) and not isinstance(pc, bool) and pc >= 0 else 0
        for k in _BOOL_FIELDS:
            if k in c and not isinstance(c[k], bool):
                del c[k]
        out.append(c)
    return out


def strip_html(s):
    return html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


def flags_of(b):
    out = []
    if "Passwords" in b.get("DataClasses", []):
        out.append("passwords")
    for key, label in (("IsVerified", "unverified"), ("IsFabricated", "fabricated"), ("IsSensitive", "sensitive"),
                       ("IsSpamList", "spam list"), ("IsMalware", "malware"), ("IsStealerLog", "stealer logs")):
        val = b.get(key)
        if (key == "IsVerified" and val is False) or (key != "IsVerified" and val):
            out.append(label)
    return out


def prep(raw):
    """Display copies with search text; never mutates `raw` (which is what gets cached)."""
    out = []
    for b in raw:
        d = dict(b)
        d["_desc"] = strip_html(b["Description"])
        d["_text"] = " ".join((b["Title"], b["Domain"], b["Name"], " ".join(b["DataClasses"]), d["_desc"])).lower()
        out.append(d)
    return out


def age_text(ts):
    days = int((time.time() - ts) // 86400)
    return "today" if days < 1 else f"{days} day{'s' if days != 1 else ''} ago"


def load_cache_blob(path):
    """-> (fetched_ts, cleaned_raw). Raises OSError / ValueError on anything unusable."""
    with open(path, encoding="utf-8") as fh:
        blob = json.load(fh)
    if not isinstance(blob, dict):
        raise BadResponse("cache is not an object")
    fetched = blob.get("fetched")
    if not isinstance(fetched, (int, float)) or isinstance(fetched, bool):
        raise BadResponse("cache timestamp invalid")
    return float(fetched), clean_breaches(blob.get("data"))


def save_cache(path, raw):
    """Atomic write (temp file + os.replace) so a crash mid-write can't leave a torn cache."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"fetched": time.time(), "data": raw}, fh)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        return True
    except OSError:
        return False
