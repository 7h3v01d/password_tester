# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
from password_tester import wordlists
from password_tester.engine import Analyzer


def test_bundled_lists_feed_the_dictionary(tmp_path):
    (tmp_path / "passwords").mkdir()
    (tmp_path / "words").mkdir()
    (tmp_path / "passwords" / "top.txt").write_text("Wallstreet7\nhunter2\n\n")
    (tmp_path / "words" / "eff.txt").write_text("11111\twall\n11112\tstreet\n11113\tab\n")
    pw, words = wordlists.bundled_lists(str(tmp_path))
    assert pw == {"wallstreet7", "hunter2"} and words == {"wall", "street"}
    az = Analyzer()
    before = az.analyze("Wallstreet-Zq")["score"]
    az.words |= words
    assert az.analyze("Wallstreet-Zq")["score"] < before


def test_password_list_respects_limit(tmp_path):
    p = tmp_path / "l.txt"
    p.write_text("\n".join(f"pw{i}" for i in range(100)))
    assert len(wordlists.read_password_list(str(p), limit=10)) == 10
