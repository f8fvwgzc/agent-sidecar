#!/usr/bin/env python3
"""Security grep over the agent timeline view, ui/js/timeline (design docs/design/agent-platform.md
§11, §11.1): no HTML parsing sinks, no eval, no inline handlers or styles set from script, no
remote imports, and d3 only through globalThis.d3 (it is a classic script).

Run from anywhere: python3 -I ui/tests/check_timeline.py   (stdlib only; exit status 1 on failure)
"""

import re
import sys
from pathlib import Path

UI = Path(__file__).resolve().parent.parent
JS_DIR = UI / "js" / "timeline"

errors = []


def fail(msg):
    errors.append(msg)


FORBIDDEN = [
    (r"\.html\s*\(", ".html() (d3/jQuery HTML setter)"),
    (r"\binnerHTML\b", "innerHTML"),
    (r"\bouterHTML\b", "outerHTML"),
    (r"\binsertAdjacentHTML\b", "insertAdjacentHTML"),
    (r"\bcreateContextualFragment\b", "createContextualFragment"),
    (r"\bDOMParser\b", "DOMParser"),
    (r"\bdocument\.write(ln)?\s*\(", "document.write"),
    (r"(?<![\w.])eval\s*\(", "eval"),
    (r"\bnew\s+Function\b", "new Function"),
    (r"\bset(Timeout|Interval)\s*\(\s*[\"'`]", "string passed to setTimeout/setInterval"),
    (r"setAttribute\s*\(\s*[\"'`]on", "inline event handler via setAttribute"),
    (r"\.attr\s*\(\s*[\"'`]on", "inline event handler via d3 .attr"),
    (r"setAttribute\s*\(\s*[\"'`]style[\"'`]", "inline style attribute"),
    (r"\.attr\s*\(\s*[\"'`]style[\"'`]", "inline style attribute via d3 .attr"),
    (r"<\s*script", "script markup in a string"),
    (r"javascript\s*:", "javascript: URL"),
    (r"\bimport\s*\(\s*[\"'`]https?:", "remote dynamic import"),
    (r"^\s*import\s[^;]*from\s*[\"'`]https?:", "remote import"),
]


def strip_comments(src):
    # Line and block comments; good enough for our own sources (no regex literals with //).
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"(^|[^:\\])//[^\n]*", r"\1", src)


def check_js():
    files = sorted(JS_DIR.glob("*.js"))
    if not files:
        fail("no files in ui/js/timeline")
    for path in files:
        src = strip_comments(path.read_text(encoding="utf-8"))
        for lineno, line in enumerate(src.splitlines(), 1):
            for pattern, what in FORBIDDEN:
                if re.search(pattern, line):
                    fail("%s:%d: forbidden %s" % (path.relative_to(UI), lineno, what))
        if re.search(r"\bwindow\.d3\b|\bimport\s+[^;]*\bd3\b[^;]*from", src):
            fail("%s: use globalThis.d3 (d3 is a classic script)" % path.relative_to(UI))
    return len(files)


def selftest():
    """The patterns must catch known-bad lines and pass known-good ones."""
    bad = ["el.innerHTML = t", "sel.html(t)", "eval(x)", "setTimeout('x()', 1)", "el.setAttribute('onclick', f)", "import('https://x/y.js')"]
    good = ["el.textContent = t", "sel.text(t)", "setTimeout(run, 1)", "el.addEventListener('click', f)", "const evaluate = 1"]
    for line in bad:
        assert any(re.search(p, line) for p, _ in FORBIDDEN), "selftest: not caught: %s" % line
    for line in good:
        assert not any(re.search(p, line) for p, _ in FORBIDDEN), "selftest: false positive: %s" % line


def main():
    selftest()
    n = check_js()
    if errors:
        for e in errors:
            print("FAIL", e)
        print("%d problem(s)" % len(errors))
        return 1
    print("ok: %d file(s) in ui/js/timeline pass the security grep" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
