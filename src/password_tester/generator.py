# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Random password and passphrase generation with entropy taken from the generation process."""
import math
import secrets
import string

from . import data

AMBIGUOUS = "Il1O0o"


def gen_random(length, upper=True, lower=True, digits=True, symbols=True, no_amb=False):
    sets = []
    for on, chars in ((lower, string.ascii_lowercase), (upper, string.ascii_uppercase),
                      (digits, string.digits), (symbols, data.SYMBOLS)):
        if on:
            sets.append("".join(c for c in chars if not (no_amb and c in AMBIGUOUS)))
    if not sets:
        return None, 0.0
    pool = "".join(sets)
    chars = [secrets.choice(s) for s in sets]                      # one from each chosen class
    chars += [secrets.choice(pool) for _ in range(max(0, length - len(chars)))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars), len(chars) * math.log2(len(pool))


def gen_phrase(n, sep="-", cap=True, num=True, sym=True, words=data.WORDS):
    picked = [secrets.choice(words) for _ in range(n)]
    if cap:
        picked = [w.capitalize() for w in picked]
    pw, bits = sep.join(picked), n * math.log2(len(words))
    if num:
        pw += str(secrets.randbelow(90) + 10)
        bits += math.log2(90)
    if sym:
        pw += secrets.choice(data.SYMBOLS)
        bits += math.log2(len(data.SYMBOLS))
    return pw, bits
