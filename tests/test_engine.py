# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
import secrets
import string
import time

import pytest

from password_tester import data
from password_tester.engine import Analyzer, Finding, checklist, crack_time, extend
from password_tester.generator import gen_random

ALPHA = string.ascii_letters + string.digits + data.SYMBOLS


def rand(n):
    return "".join(secrets.choice(ALPHA) for _ in range(n))


@pytest.fixture
def az():
    return Analyzer()


@pytest.mark.parametrize("n", [157, 160, 200, 1000, 5000])
def test_long_random_passwords_do_not_overflow(az, n):
    r = az.analyze(rand(n))                      # v3 raised OverflowError from ~157 chars
    assert r["crack_time"] == "trillions of years"


def test_crack_time_handles_absurd_bit_counts():
    assert crack_time(10_000, 1e2) == "trillions of years"
    assert crack_time(0, 1e10) == "instantly"


def test_analysis_cost_is_bounded(az):
    t = time.perf_counter()
    az.analyze(rand(5000))
    assert time.perf_counter() - t < 1.0


@pytest.mark.parametrize("pw, fragment", [("f00tba11", "f00tba11"), ("he11o", "he11o"), ("Wa1rus-f1ower", "f1ower")])
def test_one_read_as_l_is_detected(az, pw, fragment):
    az.words |= {"flower"}
    segs = az.analyze(pw)["segments"]
    assert (fragment, "dict") in segs, segs


def test_leet_word_scores_like_its_plain_word(az):
    assert az.analyze("f00tba11")["score"] <= 10   # v3 gave 51 vs 3 for "football"


def test_extend_claims_only_its_random_tail():
    cand, bits = extend("Wallstreet7")
    assert cand.startswith("Wallstreet7") and len(cand) == len("Wallstreet7") + 10
    assert 60 <= bits <= 66


def test_extend_refuses_empty():
    assert extend("") == (None, 0.0)


def test_three_char_personal_token_needs_a_boundary(az):
    az.personal = {"tan", "rex"}
    assert not any(k == "personal" for _, k in az.analyze("Important-Zebra-77")["segments"])
    assert any(k == "personal" for _, k in az.analyze("Rex2019!zz")["segments"])


def test_finding_masking_never_includes_fragment():
    f = Finding("Keyboard pattern {}.", "qwerty")
    assert "qwerty" not in f.render("mask") and "6 hidden" in f.render("mask")
    assert f.render("omit") == "Keyboard pattern."
    assert "'qwerty'" in f.render("show")


def test_checklist_agrees_with_engine(az):
    for _ in range(300):
        pw = gen_random(18)[0]
        r = az.analyze(pw)
        clean = dict(checklist(pw, r))["No common patterns"]
        assert clean == (not r["common"] and all(k == "brute" for _, k in r["segments"]))


def test_unicode_lowercase_length_change_does_not_misalign(az):
    r = az.analyze("İstanbul2024!")
    assert "".join(t for t, _ in r["segments"]) == "İstanbul2024!"
