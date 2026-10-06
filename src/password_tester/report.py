# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Export reports. Without 'include password', nothing that reveals the password's content leaves."""
import datetime
import json

from .engine import ATTACKS, KIND_LABEL, crack_time


def build_report(pw, result, breach_msg, include_pw):
    reveal = "show" if include_pw else "omit"
    patterns = [{"type": KIND_LABEL[k], **({"length": len(t), "text": t} if include_pw else {})}
                for t, k in result["segments"] if k != "brute"]
    return {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "password": pw if include_pw else f"(hidden, {len(pw)} characters)",
        "grade": result["grade"], "score": result["score"],
        "effective_entropy_bits": round(result["entropy"], 1),
        "crack_times": {name: crack_time(result["entropy"], rate) for name, rate in ATTACKS},
        "breach_check": breach_msg or "not checked",
        "patterns": patterns,
        "findings": [f.render(reveal) for f in result["findings"]],
        "recommendations": result["tips"],
    }


def render_text(d):
    out = ["PASSWORD STRENGTH REPORT", "=" * 24,
           f"Generated : {d['generated']}", f"Password  : {d['password']}",
           f"Grade     : {d['grade']} ({d['score']}/100)", f"Entropy   : ~{d['effective_entropy_bits']} bits",
           f"Breach    : {d['breach_check']}", "", "Time to crack (average)"]
    out += [f"  - {k}: {v}" for k, v in d["crack_times"].items()]
    out += ["", "Patterns found"]
    out += [f"  - {p['type']}" + (f" ({p['length']} chars): {p['text']}" if "text" in p else "")
            for p in d["patterns"]] or ["  none"]
    out += ["", "Findings"] + [f"  - {x}" for x in d["findings"]]
    out += ["", "Recommendations"] + ([f"  - {x}" for x in d["recommendations"]] or ["  none"])
    return "\n".join(out) + "\n"


def write_report(path, d):
    """Raises OSError on failure; the caller reports it."""
    with open(path, "w", encoding="utf-8") as fh:
        if path.lower().endswith(".json"):
            json.dump(d, fh, indent=2, ensure_ascii=False)
        else:
            fh.write(render_text(d))
