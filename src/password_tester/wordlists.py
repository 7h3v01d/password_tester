# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Loading external lists. All functions are pure file readers, safe to run on a worker thread."""
import glob
import os

MAX_PASSWORDS = 5_000_000
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")


def read_password_list(path, limit=MAX_PASSWORDS):
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().lower()
            if w:
                out.add(w)
                if len(out) >= limit:
                    break
    return out


def read_word_list(path):
    """One word per line; diceware '11111<tab>word' format OK."""
    found = set()
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            parts = line.split()
            if parts and parts[-1].isalpha() and 3 <= len(parts[-1]) <= 12:
                found.add(parts[-1].lower())
    return found


def bundled_lists(root=DATA_DIR):
    """Auto-load anything dropped into data/passwords/*.txt and data/words/*.txt."""
    pw, words = set(), set()
    for p in sorted(glob.glob(os.path.join(root, "passwords", "*.txt"))):
        pw |= read_password_list(p, MAX_PASSWORDS - len(pw))
        if len(pw) >= MAX_PASSWORDS:
            break
    for p in sorted(glob.glob(os.path.join(root, "words", "*.txt"))):
        words |= read_word_list(p)
    return pw, words
