# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Pattern-aware (zxcvbn-style) strength analysis. Pure Python: no Tk, no network.

The password is explained as the cheapest sequence of guessable pieces (dictionary words, l33t
words, personal info, keyboard walks, sequences, repeats, dates); whatever is left is costed as
brute force. Bits are log2(guesses).
"""
import math
import re
from dataclasses import dataclass

from . import data
from .generator import gen_random

MAX_TOKEN = 32            # longest word/walk/repeat chunk we try to match: keeps analysis ~linear
MAX_ANALYZE = 256         # pattern-match this many chars; the rest is costed as brute force
GRADES = ((0, "Very Weak"), (20, "Weak"), (40, "Fair"), (60, "Strong"), (80, "Very Strong"))
ATTACKS = (
    ("Online, rate-limited login (100 guesses/s)", 1e2),
    ("Offline, slow hash e.g. bcrypt (20 thousand/s)", 2e4),
    ("Offline, fast hash e.g. MD5/SHA-1 (10 billion/s)", 1e10),
    ("Large cracking cluster (1 trillion/s)", 1e12),
)
KIND_LABEL = {"dict": "word", "personal": "personal info", "keyboard": "keyboard walk",
              "sequence": "sequence", "repeat": "repeat", "date": "date / year", "brute": "random"}

# l33t: unambiguous swaps, plus the two that could be either i or l ("he11o", "1nternet").
_LEET = {"@": "a", "4": "a", "3": "e", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t",
         "8": "b", "6": "g", "9": "g"}
_AMBIG = {"1": "il", "|": "il"}


@dataclass(frozen=True)
class Finding:
    text: str                 # "{}" marks where the matched fragment goes, if any
    fragment: str = ""
    tip: str = ""

    def render(self, reveal="show"):
        """reveal: 'show' -> 'qwerty'; 'mask' -> (6 hidden characters); 'omit' -> nothing."""
        if "{}" not in self.text:
            return self.text
        if reveal == "show":
            part = f" '{self.fragment}'"
        elif reveal == "mask":
            part = f" ({len(self.fragment)} hidden character{'s' if len(self.fragment) != 1 else ''})"
        else:
            part = ""
        return self.text.replace(" {}", part)


def grade_for(score):
    level, label = 0, GRADES[0][1]
    for i, (minimum, lab) in enumerate(GRADES):
        if score >= minimum:
            level, label = i, lab
    return level, label


def pool_size(pw):
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        pool += 32
    return pool


def format_duration(seconds):
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 365), ("year", 1000),
             ("thousand year", 1000), ("million year", 1000), ("billion year", 1000)]
    value = seconds
    for name, size in units:
        if value < size:
            n = int(value)
            return f"{n} {name}{'' if n == 1 else 's'}"
        value /= size
    return "trillions of years"


def crack_time(bits, rate):
    """Average time to crack. Worked in log space: 2**bits overflows a float past ~1024 bits."""
    if bits <= 0:
        return "instantly"
    log2_seconds = bits - 1 - math.log2(rate)
    if log2_seconds > 100:                      # ~4e22 years; well past "trillions"
        return "trillions of years"
    return format_duration(2.0 ** log2_seconds)


def _lower_same_length(pw):
    # str.lower() can change length ('İ' -> 'i̇'), which would misalign every slice below.
    return "".join(c.lower() if len(c.lower()) == 1 else c for c in pw)


def leet_variants(low):
    """De-l33t a lowercased string, trying both readings of ambiguous chars. Length preserved."""
    out = []
    for k in (0, 1):
        v = "".join(_AMBIG[c][k] if c in _AMBIG else _LEET.get(c, c) for c in low)
        if v != low and v not in out:
            out.append(v)
    return out


def _case_bits(orig):
    letters = [c for c in orig if c.isalpha()]
    if not letters or all(c.islower() for c in letters):
        return 0
    ups = sum(c.isupper() for c in letters)
    if ups == len(letters) or (letters[0].isupper() and ups == 1):
        return 1
    return 2 + min(ups, len(letters) - ups)


def _is_date(s):
    if len(s) == 8:
        opts = [(s[:2], s[2:4], s[4:]), (s[2:4], s[:2], s[4:]), (s[6:], s[4:6], s[:4])]
    else:
        opts = [(s[:2], s[2:4], s[4:]), (s[2:4], s[:2], s[4:]), (s[4:], s[2:4], s[:2])]
    for d, m, y in opts:
        if 1 <= int(d) <= 31 and 1 <= int(m) <= 12 and (len(y) == 2 or 1900 <= int(y) <= 2099):
            return True
    return False


def personal_tokens(names, email, dates, other):
    toks = set()

    def add(t):
        t = re.sub(r"[^a-z0-9]", "", t.lower())
        if len(t) >= 3:
            toks.add(t)

    words = [w for w in re.split(r"[^A-Za-z0-9]+", names) if w]
    for w in words:
        add(w)
    if len(words) > 1:
        add("".join(words))
        add("".join(reversed(words)))
    local = email.split("@")[0]
    for w in re.split(r"[._\-+]+", local):
        add(w)
    add(local)
    for chunk in re.split(r"[,;]+", dates):
        parts = [p for p in re.split(r"\D+", chunk) if p]
        if len(parts) == 3:
            idx = next((i for i, p in enumerate(parts) if len(p) == 4), 2)
            y = parts[idx]
            a, b = [p.zfill(2) for i, p in enumerate(parts) if i != idx]
            y2 = y[-2:]
            for combo in (a + b + y, b + a + y, y + a + b, y + b + a, a + b + y2, b + a + y2,
                          y2 + a + b, y2 + b + a, a + b, b + a, y):
                add(combo)
        elif len(parts) == 1:
            add(parts[0])
    for w in re.split(r"[,;\s]+", other):
        add(w)
    return toks


class Analyzer:
    """Holds the dictionaries; `analyze()` is pure given that state."""

    def __init__(self):
        self.words = set(data.WORDS) | set(data.COMMON_WORDS) | set(data.NAMES)
        self.common = set(data.COMMON_PASSWORDS)
        self.personal = set()

    # ---- matching
    def _dict_bits(self):
        return max(11.0, math.log2(len(self.words) + len(self.common)))

    def _find_matches(self, pw, brute):
        n, low = len(pw), _lower_same_length(pw)
        variants = leet_variants(low)
        dict_bits = self._dict_bits()
        found = []
        for i in range(n):
            for j in range(i + 3, min(n, i + MAX_TOKEN) + 1):
                size, orig, sl = j - i, pw[i:j], low[i:j]
                for cand in dict.fromkeys([sl] + [v[i:j] for v in variants]):
                    subs = sum(a != b for a, b in zip(sl, cand))
                    extra = _case_bits(orig) + min(subs, 4)
                    if cand in self.personal and (size > 3 or self._at_boundary(pw, i, j)):
                        found.append((i, j, "personal", 5 + extra, orig))
                    if size >= 4 and (cand in self.words or cand in self.common):
                        found.append((i, j, "dict", dict_bits + extra, orig))
                if size >= 4 and any(sl in r or sl in r[::-1] for r in data.KEYBOARD_ROWS):
                    found.append((i, j, "keyboard", 5 + math.log2(size), orig))
                if sl.isalnum() and {ord(b) - ord(a) for a, b in zip(sl, sl[1:])} in ({1}, {-1}):
                    found.append((i, j, "sequence", 6 + math.log2(size), orig))
                if sl.isdigit() and ((size == 4 and re.fullmatch(r"(19|20)\d\d", sl)) or
                                     (size in (6, 8) and _is_date(sl))):
                    found.append((i, j, "date", 7 if size == 4 else 16, orig))
        for size in range(1, min(n // 2, MAX_TOKEN) + 1):                  # repeated chunks
            for i in range(n - 2 * size + 1):
                base, k = pw[i:i + size], 1
                while pw[i + k * size:i + (k + 1) * size] == base:
                    k += 1
                if (size == 1 and k >= 3) or (size > 1 and k >= 2):
                    found.append((i, i + k * size, "repeat", size * brute + math.log2(k), pw[i:i + k * size]))
        return found

    @staticmethod
    def _at_boundary(pw, i, j):
        # 3-char personal tokens ("Rex", "Tan") only count when not buried inside a longer word,
        # so "Tan" doesn't flag "important".
        return i == 0 or not pw[i - 1].isalpha() or j == len(pw) or not pw[j].isalpha()

    @staticmethod
    def _segment(pw, matches, brute):
        """Cheapest way to explain the password (dynamic programming)."""
        n = len(pw)
        best, back, by_end = [0.0] * (n + 1), [None] * (n + 1), {}
        for m in matches:
            by_end.setdefault(m[1], []).append(m)
        for i in range(1, n + 1):
            best[i] = best[i - 1] + brute
            for m in by_end.get(i, []):
                cost = best[m[0]] + m[3]
                if cost < best[i]:
                    best[i], back[i] = cost, m
        segs, i = [], n
        while i > 0:
            m = back[i]
            if m is None:
                segs.append((pw[i - 1], "brute"))
                i -= 1
            else:
                segs.append((m[4], m[2]))
                i = m[0]
        merged = []
        for text, kind in reversed(segs):
            if merged and kind == "brute" and merged[-1][1] == "brute":
                merged[-1] = (merged[-1][0] + text, "brute")
            else:
                merged.append((text, kind))
        return best[n], merged

    def is_common(self, pw):
        low = _lower_same_length(pw)
        return low in self.common or any(v in self.common for v in leet_variants(low))

    # ---- public
    def analyze(self, pw):
        if not pw:
            return None
        n = len(pw)
        brute = math.log2(pool_size(pw))
        head = pw[:MAX_ANALYZE]
        bits, segs = self._segment(head, self._find_matches(head, brute), brute)
        if n > MAX_ANALYZE:                      # far beyond any realistic attack either way
            bits += (n - MAX_ANALYZE) * brute
            segs = segs[:-1] + [(segs[-1][0] + pw[MAX_ANALYZE:], "brute")] if segs[-1][1] == "brute" \
                else segs + [(pw[MAX_ANALYZE:], "brute")]
        common = self.is_common(pw)
        findings, seen = [], set()
        if common:
            findings.append(Finding("This is one of the most commonly used passwords.",
                                    tip="Avoid well-known passwords entirely; attackers try them first."))
        for text, kind in segs:
            key = (kind, text.lower())
            if kind == "brute" or key in seen:
                continue
            seen.add(key)
            if kind == "dict" and not common:
                findings.append(Finding("Contains the common word {}.", text,
                                        "Skip dictionary words, or chain several unrelated ones into a long passphrase."))
                if text.lower() not in self.words and text.lower() not in self.common:
                    findings.append(Finding("Look-alike swaps (@ for a, 1 for l) are well known to attackers.",
                                            tip="Substitutions like 3 for e add almost no strength; add length instead."))
            elif kind == "personal":
                findings.append(Finding("Contains personal info {} that anyone who knows you could guess.", text,
                                        "Keep names, birthdays and email handles out of your passwords."))
            elif kind == "keyboard":
                findings.append(Finding("Keyboard pattern {}.", text, "Avoid keys that sit next to each other."))
            elif kind == "sequence":
                findings.append(Finding("Predictable sequence {}.", text, "Avoid runs like abc or 321."))
            elif kind == "repeat":
                findings.append(Finding("Repeated characters or chunks {}.", text,
                                        "Repeats add length but almost no strength."))
            elif kind == "date":
                findings.append(Finding("Looks like a date or year {}.", text,
                                        "Dates are among the first things attackers try."))
        if n < 8:
            findings.append(Finding(f"Too short ({n} characters).", tip="Use at least 12 characters; 14-16+ is better."))
        elif n < 12:
            findings.append(Finding(f"Fairly short ({n} characters).",
                                    tip="Add more length: each extra character multiplies the work for attackers."))
        missing = [name for name, ok in (("lowercase letters", re.search(r"[a-z]", pw)),
                                         ("uppercase letters", re.search(r"[A-Z]", pw)),
                                         ("numbers", re.search(r"\d", pw)),
                                         ("symbols (!@#$...)", re.search(r"[^A-Za-z0-9]", pw))) if not ok]
        if missing:
            findings.append(Finding("Missing " + ", ".join(missing) + ".", tip="Mix in " + ", ".join(missing) + "."))

        score = int(min(100, bits / 80 * 100))
        if common:
            score = min(score, 3)
        if n < 8:
            score = min(score, 30)
        level, grade = grade_for(score)
        return {"score": score, "grade": grade, "level": level, "entropy": bits, "length": n,
                "segments": segs, "findings": findings, "common": common,
                "tips": list(dict.fromkeys(f.tip for f in findings if f.tip)),
                "crack_time": crack_time(bits, 1e10)}


def checklist(pw, result):
    """Requirement ticks. 'No common patterns' now agrees with the engine instead of v1's regexes."""
    clean = bool(result) and not result["common"] and all(k == "brute" for _, k in result["segments"])
    return [
        ("12+ characters", len(pw) >= 12),
        ("Lowercase", bool(re.search(r"[a-z]", pw))),
        ("Uppercase", bool(re.search(r"[A-Z]", pw))),
        ("Number", bool(re.search(r"\d", pw))),
        ("Symbol", bool(re.search(r"[^A-Za-z0-9]", pw))),
        ("No common patterns", clean),
    ]


def extend(pw, tail=10):
    """Your password + a truly random tail. Returns (candidate, random_bits) or (None, 0).

    Honest by construction: the strength claimed is ONLY the random tail, so it holds even if an
    attacker already knows your old password. (v1's strengthen() leaned on case/l33t tweaks that
    cracking rules try first and claimed ~105 bits for ~40.)
    """
    base = pw.strip()
    if not base or len(base) > 64:
        return None, 0.0
    rand, bits = gen_random(tail)
    return base + rand, bits
