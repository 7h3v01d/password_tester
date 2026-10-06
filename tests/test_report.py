# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
import json

from password_tester.engine import Analyzer, personal_tokens
from password_tester.report import build_report, render_text

PW = "Jane1990qwerty!"


def _result():
    az = Analyzer()
    az.personal = personal_tokens("Jane Tan", "", "", "")
    return az.analyze(PW)


def test_hidden_export_leaks_no_fragments():
    d = build_report(PW, _result(), "", include_pw=False)
    blob = json.dumps(d) + render_text(d)
    for frag in ("Jane", "jane", "1990", "qwerty"):
        assert frag not in blob, frag


def test_included_export_has_fragments():
    d = build_report(PW, _result(), "", include_pw=True)
    assert PW in json.dumps(d) and "qwerty" in render_text(d)
