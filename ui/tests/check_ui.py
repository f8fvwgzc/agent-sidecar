#!/usr/bin/env python3
"""Static checks for the agentsc console (design §11 "Security" and §15 rule 10).

Standard library only. Run from the repository root:

    python3 -I ui/tests/check_ui.py            # static checks, then the node unit tests if node exists
    python3 -I ui/tests/check_ui.py --no-node  # static checks only

It fails when:

* a script under ui/js uses a forbidden API: d3 `.html(`, `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `createContextualFragment`, `DOMParser`, `document.write`, `eval(`,
  `new Function` / `Function(`, string timers, `javascript:` URLs, `srcdoc`, event-handler or
  style attributes set from script, or a remote import;
* an HTML or SVG file under ui/ (vendor excluded) has an inline event attribute
  (`on<event>=`), a `style` attribute, a `<style>` element, an inline `<script>` without
  `src`, a remote script or stylesheet, or a frame/object/base element;
* index.html does not load exactly the pinned d3 (classic script) before js/main.js (module);
* a relative module import does not resolve to a file;
* ui/vendor/SHA256SUMS is missing, malformed, lists a file whose SHA-256 differs, or leaves a
  vendored script unlisted;
* styles.css imports or references remote resources.

The detectors test themselves on known-bad and known-good samples before scanning.
"""

from __future__ import annotations

import hashlib
import html.parser
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

UI = pathlib.Path(__file__).resolve().parent.parent
JS_DIR = UI / "js"
VENDOR = UI / "vendor"
SKIP_DIRS = {"vendor", "tests"}

D3_SCRIPT = "vendor/d3.v7.9.0.min.js"
MAIN_SCRIPT = "js/main.js"

FORBIDDEN_JS: list[tuple[str, re.Pattern[str]]] = [
    ("d3 .html( inserts markup", re.compile(r"\.html\s*\(")),
    ("innerHTML", re.compile(r"innerHTML")),
    ("outerHTML", re.compile(r"outerHTML")),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML")),
    ("createContextualFragment", re.compile(r"createContextualFragment")),
    ("DOMParser parses markup", re.compile(r"\bDOMParser\b")),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write")),
    ("eval(", re.compile(r"(?<![\w$])eval\s*\(")),
    ("new Function", re.compile(r"\bnew\s+Function\b")),
    ("Function( constructor", re.compile(r"(?<![\w$.])Function\s*\(")),
    ("string passed to a timer", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")),
    ("javascript: URL", re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("srcdoc", re.compile(r"\bsrcdoc\b", re.IGNORECASE)),
    (
        "event-handler attribute set from script",
        re.compile(r"\.(?:setAttribute|attr|setAttributeNS)\s*\(\s*(?:[^,()]*,\s*)?['\"`]on", re.IGNORECASE),
    ),
    (
        "style attribute set from script (CSP style-src 'self')",
        re.compile(r"\.(?:setAttribute|attr)\s*\(\s*['\"`]style['\"`]", re.IGNORECASE),
    ),
    ("remote module import", re.compile(r"(?:\bfrom\s*|\bimport\s*\(\s*)['\"`](?:[a-z]+:)?//", re.IGNORECASE)),
    ("importScripts", re.compile(r"\bimportScripts\b")),
    (
        "the session token must never be stored",
        re.compile(r"(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\([^)]*token", re.IGNORECASE),
    ),
]

IMPORT_RE = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(\s*|^\s*import\s+)['"]([^'"]+)['"]""", re.MULTILINE)


def scan_js(text: str) -> list[tuple[int, str]]:
    """Forbidden API uses as (line, rule) pairs."""
    found = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule, rx in FORBIDDEN_JS:
            if rx.search(line):
                found.append((lineno, rule))
    return found


class MarkupScanner(html.parser.HTMLParser):
    """Collects inline handlers, inline styles, inline scripts and remote resources."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.problems: list[tuple[int, str]] = []
        self.scripts: list[tuple[str | None, str | None]] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        line = self.getpos()[0]
        names = {k.lower(): (v or "") for k, v in attrs}
        for k, v in names.items():
            if k.startswith("on"):
                self.problems.append((line, f"inline event attribute {k}= on <{tag}>"))
            if k == "style":
                self.problems.append((line, f"style attribute on <{tag}>"))
            if k in {"href", "src", "action", "formaction", "xlink:href"} and re.match(
                r"\s*javascript:", v, re.IGNORECASE
            ):
                self.problems.append((line, f"javascript: URL in {k} on <{tag}>"))
            if k == "srcdoc":
                self.problems.append((line, f"srcdoc on <{tag}>"))
        if tag == "style":
            self.problems.append((line, "<style> element (use styles.css)"))
        if tag in {"iframe", "frame", "object", "embed", "base", "applet"}:
            self.problems.append((line, f"<{tag}> element"))
        if tag == "script":
            src = names.get("src")
            self.scripts.append((src, names.get("type")))
            if not src:
                self.problems.append((line, "inline <script> without src"))
            elif re.match(r"\s*(?:[a-z][a-z0-9+.-]*:)?//", src, re.IGNORECASE) or ":" in src.split("/")[0]:
                self.problems.append((line, f"remote script {src}"))
            self._in_script = True
        if tag == "link" and "stylesheet" in names.get("rel", "").lower():
            href = names.get("href", "")
            if re.match(r"\s*(?:[a-z][a-z0-9+.-]*:)?//", href, re.IGNORECASE):
                self.problems.append((line, f"remote stylesheet {href}"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.problems.append((self.getpos()[0], "inline script content"))


def scan_markup(text: str) -> MarkupScanner:
    s = MarkupScanner()
    s.feed(text)
    s.close()
    return s


CSS_REMOTE = re.compile(r"@import|url\(\s*['\"]?\s*(?:[a-z]+:)?//", re.IGNORECASE)


def scan_css(text: str) -> list[tuple[int, str]]:
    return [
        (n, "remote resource or @import in CSS")
        for n, line in enumerate(text.splitlines(), 1)
        if CSS_REMOTE.search(line)
    ]


def check_sums(vendor: pathlib.Path) -> list[str]:
    """Problems with vendor/SHA256SUMS (empty list = every vendored file matches)."""
    sums = vendor / "SHA256SUMS"
    if not sums.is_file():
        return [f"{sums} is missing"]
    problems = []
    listed = set()
    lines = [ln for ln in sums.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not lines:
        problems.append(f"{sums} lists no file")
    for ln in lines:
        m = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\]+)", ln.strip())
        if not m:
            problems.append(f"{sums}: malformed line {ln!r}")
            continue
        want, name = m.groups()
        listed.add(name)
        f = vendor / name
        if not f.is_file():
            problems.append(f"{sums}: {name} does not exist")
            continue
        got = hashlib.sha256(f.read_bytes()).hexdigest()
        if got != want:
            problems.append(f"{sums}: {name} has sha256 {got}, expected {want}")
    for f in sorted(vendor.glob("*.js")):
        if f.name not in listed:
            problems.append(f"{f} is not listed in {sums}")
    return problems


def check_index(text: str) -> list[str]:
    s = scan_markup(text)
    srcs = [src for src, _ in s.scripts]
    problems = []
    if srcs != [D3_SCRIPT, MAIN_SCRIPT]:
        problems.append(f"index.html must load exactly [{D3_SCRIPT}, {MAIN_SCRIPT}] in that order, found {srcs}")
    types = dict(s.scripts)
    if types.get(D3_SCRIPT) not in (None, "", "text/javascript"):
        problems.append("d3 must be a classic script")
    if types.get(MAIN_SCRIPT) != "module":
        problems.append('js/main.js must be type="module"')
    return problems


def check_imports(js_dir: pathlib.Path) -> list[str]:
    problems = []
    for f in sorted(js_dir.rglob("*.js")):
        name = f.relative_to(js_dir.parent)
        for m in IMPORT_RE.finditer(f.read_text(encoding="utf-8")):
            spec = m.group(1)
            if not spec.startswith(("./", "../")):
                problems.append(f"{name}: import {spec!r} is not a relative module path")
                continue
            target = (f.parent / spec).resolve()
            if not target.is_file():
                problems.append(f"{name}: import {spec!r} does not resolve")
    return problems


def selftest() -> None:
    """The detectors must catch known-bad samples and pass known-good ones."""
    bad_js = [
        "sel.html('<b>x</b>')",
        "el.innerHTML = t",
        "el.outerHTML",
        "el.insertAdjacentHTML('beforeend', t)",
        "range.createContextualFragment(t)",
        "new DOMParser()",
        "document.write(x)",
        "eval(code)",
        "window.eval(code)",
        "new Function('return 1')",
        "Function('return 1')()",
        "setTimeout('alert(1)', 10)",
        "a.href = 'javascript:alert(1)'",
        "frame.srcdoc = t",
        "el.setAttribute('onclick', f)",
        "sel.attr('onmouseover', f)",
        "el.setAttributeNS(null, 'onload', f)",
        "el.setAttribute('style', 'color:red')",
        "import x from 'https://cdn.example/x.js'",
        "await import('//cdn.example/x.js')",
        "localStorage.setItem('t', token)",
    ]
    good_js = [
        "sel.text(label)",
        "el.textContent = t",
        "sel.on('click', f)",
        "el.addEventListener('click', f)",
        "el.style.left = `${x}px`",
        "sel.attr('class', 'node')",
        "import { h } from './dom.js'",
        "if (typeof x === 'function') x()",
        "const evaluate = (v) => v",
        "setTimeout(run, 10)",
    ]
    for s in bad_js:
        assert scan_js(s), f"selftest: not caught: {s}"
    for s in good_js:
        assert not scan_js(s), f"selftest: false positive: {s} -> {scan_js(s)}"
    bad_html = [
        '<button onclick="go()">x</button>',
        '<div style="color:red"></div>',
        "<style>p{}</style>",
        "<script>alert(1)</script>",
        '<script src="https://cdn.example/x.js"></script>',
        '<link rel="stylesheet" href="//fonts.example/x.css">',
        '<a href="javascript:alert(1)">x</a>',
        '<iframe src="x.html"></iframe>',
        '<svg><circle onload="x()"/></svg>',
    ]
    for s in bad_html:
        assert scan_markup(s).problems, f"selftest: markup not caught: {s}"
    good = scan_markup(
        '<script src="js/main.js" type="module"></script><link rel="stylesheet" href="styles.css"><p class="x">ok</p>'
    )
    assert not good.problems, f"selftest: markup false positive: {good.problems}"
    assert scan_css("@import url(https://x/y.css);") and scan_css("a{background:url(//x/y.png)}")
    assert not scan_css('a{background-image:url("data:image/svg+xml,%3Csvg%3E")}')
    assert (
        check_index('<script src="vendor/d3.v7.9.0.min.js"></script><script type="module" src="js/main.js"></script>')
        == []
    )
    assert check_index(
        '<script type="module" src="js/main.js"></script><script src="vendor/d3.v7.9.0.min.js"></script>'
    )
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "lib.js").write_bytes(b"x")
        good = hashlib.sha256(b"x").hexdigest()
        (d / "SHA256SUMS").write_text(f"{good}  lib.js\n", encoding="utf-8")
        assert check_sums(d) == [], check_sums(d)
        (d / "SHA256SUMS").write_text(f"{'0' * 64}  lib.js\n", encoding="utf-8")
        assert any("expected" in p for p in check_sums(d)), "hash mismatch not caught"
        (d / "SHA256SUMS").write_text(f"{good}  lib.js\n", encoding="utf-8")
        (d / "extra.js").write_bytes(b"y")
        assert any("not listed" in p for p in check_sums(d)), "unlisted script not caught"
        (d / "SHA256SUMS").write_text("", encoding="utf-8")
        assert check_sums(d), "empty SHA256SUMS not caught"
        js = d / "js"
        js.mkdir()
        (js / "a.js").write_text("import { b } from './b.js';\nimport x from 'lodash';\n", encoding="utf-8")
        found = check_imports(js)
        assert any("does not resolve" in p for p in found) and any("not a relative" in p for p in found), found


def run_node_tests() -> int:
    node = shutil.which("node")
    if not node:
        print("node tests: skipped (node not found)")
        return 0
    tests = sorted(str(p) for p in (UI / "tests").glob("*.test.mjs"))
    if not tests:
        return 0
    version = subprocess.run([node, "--version"], capture_output=True, text=True, check=False).stdout.strip()
    m = re.match(r"v(\d+)\.(\d+)", version)
    # ui/js/*.js are ES modules without a package.json; node detects them from 22.7 on.
    if not m or (int(m.group(1)), int(m.group(2))) < (22, 7):
        print(f"node tests: skipped (node {version or '?'} < 22.7)")
        return 0
    print(f"node tests: {node} --test {len(tests)} file(s)", flush=True)
    return subprocess.run([node, "--test", *tests], check=False).returncode


def main(argv: list[str]) -> int:
    selftest()
    errors: list[str] = []
    js_files = sorted(JS_DIR.rglob("*.js"))
    if not js_files:
        errors.append(f"no scripts under {JS_DIR}")
    for f in js_files:
        for line, rule in scan_js(f.read_text(encoding="utf-8")):
            errors.append(f"{f.relative_to(UI)}:{line}: forbidden: {rule}")
    markup = [
        p
        for p in UI.rglob("*")
        if p.suffix in {".html", ".htm", ".svg"} and not (set(p.relative_to(UI).parts[:-1]) & SKIP_DIRS)
    ]
    for f in sorted(markup):
        for line, msg in scan_markup(f.read_text(encoding="utf-8")).problems:
            errors.append(f"{f.relative_to(UI)}:{line}: {msg}")
    index = UI / "index.html"
    if index.is_file():
        errors += [f"index.html: {p}" for p in check_index(index.read_text(encoding="utf-8"))]
    else:
        errors.append("index.html is missing")
    css = UI / "styles.css"
    if css.is_file():
        errors += [f"styles.css:{n}: {m}" for n, m in scan_css(css.read_text(encoding="utf-8"))]
    errors += check_imports(JS_DIR)
    errors += check_sums(VENDOR)
    for e in errors:
        print(e)
    print(
        f"check_ui: {len(js_files)} scripts, {len(markup)} markup files, vendor hashes checked: {'FAILED' if errors else 'ok'}",
        flush=True,
    )
    rc = 1 if errors else 0
    if "--no-node" not in argv:
        rc = rc or run_node_tests()
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
