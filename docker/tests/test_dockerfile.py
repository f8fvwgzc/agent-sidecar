"""Tests of docker/ (the images) and .github/workflows/release.yml (how they are published).

Run with `make packaging-test`. Building the images needs a Docker daemon and minutes, so
these check the files instead: stages, users, entrypoints, the build-context allowlist, the
embassy health probe (against a local HTTP server) and the release workflow's pinning,
targets and image names.
"""

from __future__ import annotations

import fnmatch
import http.server
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker/Dockerfile"
DOCKERIGNORE = ROOT / "docker/Dockerfile.dockerignore"
PROBE = ROOT / "docker/agentsc-http-ready"
RELEASE = ROOT / ".github/workflows/release.yml"


def stages() -> dict[str, list[str]]:
    """Stage name -> its instructions (continuation lines joined)."""
    text = re.sub(r"\\\n\s*", " ", DOCKERFILE.read_text())
    out: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"FROM\s+(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if m:
            current = m.group(2) or m.group(1)
            out[current] = [line]
        else:
            out[current].append(line)
    return out


def instruction(stage: list[str], keyword: str) -> list[str]:
    return [line[len(keyword) :].strip() for line in stage if line.upper().startswith(keyword + " ")]


# ---- Dockerfile ---------------------------------------------------------------------------


def test_stages_and_binary_sources() -> None:
    s = stages()
    assert set(s) == {"", "binaries-source", "binaries-prebuilt", "binaries", "agentscd", "embassy"}
    assert s[""] == ["ARG BINARIES=source"]
    assert s["binaries"] == ["FROM binaries-${BINARIES} AS binaries"]
    build = " ".join(s["binaries-source"])
    assert "cargo build --release --locked -p agentscd -p agentsc-cli -p embassy" in build
    # embassy embeds ui/ at compile time: the source stage must have it
    assert "ui ui" in instruction(s["binaries-source"], "COPY")
    prebuilt = " ".join(instruction(s["binaries-prebuilt"], "COPY"))
    for binary in ("agentscd", "agentsc", "embassy"):
        assert f"dist/linux-${{TARGETARCH}}/{binary}" in prebuilt


def test_rust_toolchain_matches_the_release_workflow() -> None:
    [base] = [line for line in stages()["binaries-source"] if line.startswith("FROM ")]
    version = re.search(r"rust:(\d+\.\d+)", base).group(1)
    workflow = yaml.safe_load(RELEASE.read_text())
    assert workflow["env"]["RUST_TOOLCHAIN"] == version


def test_agentscd_image_is_unchanged_plus_a_writable_state_dir() -> None:
    s = stages()["agentscd"]
    assert instruction(s, "ENTRYPOINT") == ['["agentscd"]']
    assert instruction(s, "USER") == ["10001:10001"]
    assert "3500 50001 50002" in instruction(s, "EXPOSE")
    run = " ".join(instruction(s, "RUN"))
    assert "install -d -o 10001 -g 10001 -m 0700 /run/agentsc/state" in run
    assert "/var/log/agentsc" in run
    copies = " ".join(instruction(s, "COPY"))
    assert "--from=binaries /out/agentscd /out/agentsc /usr/local/bin/" in copies
    assert "docker/agentsc-ready" in copies


def test_embassy_image_runs_serve_by_default_as_non_root() -> None:
    s = stages()["embassy"]
    assert instruction(s, "ENTRYPOINT") == ['["embassy"]']
    assert instruction(s, "CMD") == ['["serve"]'], "serve only through the default arguments"
    assert instruction(s, "USER") == ["10001:10001"]
    run = " ".join(instruction(s, "RUN"))
    assert "install -d -o 10001 -g 10001 -m 0700 /var/lib/agentsc" in run
    assert "install -d -o 10001 -g 10001 -m 0755 /agentsc-ca" in run
    assert "docker/agentsc-http-ready /usr/local/bin/agentsc-http-ready" in " ".join(instruction(s, "COPY"))


def ignore_rules() -> list[tuple[bool, str]]:
    rules = []
    for line in DOCKERIGNORE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rules.append((line.startswith("!"), line.lstrip("!")))
    return rules


def included(path: str) -> bool:
    """Docker's rule: the last matching pattern wins; a pattern also covers what is below it."""
    keep = True
    parts = path.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for negate, pattern in ignore_rules():
        pat = pattern.rstrip("/")
        hit = any(
            fnmatch.fnmatchcase(p, pat) or (pat.startswith("**/") and fnmatch.fnmatchcase(p.split("/")[-1], pat[3:]))
            for p in prefixes
        )
        if hit:
            keep = negate
    return keep


def test_build_context_allowlist_covers_every_copy() -> None:
    sources = []
    for stage in stages().values():
        for args in instruction(stage, "COPY"):
            if "--from=" in args:
                continue
            words = [w for w in args.split() if not w.startswith("--")]
            sources += words[:-1]
    for src in sources:
        concrete = src.replace("${TARGETARCH}", "amd64")
        assert included(concrete), f"{src} is not in the build context"
    for path in ("ui/vendor/d3.v7.9.0.min.js", "services/embassy/src/lib.rs", "dist/linux-arm64/embassy"):
        assert included(path), path
    for path in (
        "target/release/embassy",
        "services/embassy/target/x",
        "runtime/.venv/bin/python",
        ".claude/worktrees/x/Cargo.toml",
        ".git/HEAD",
        ".local/ca/ca.key",
        "deploy/compose/.env",
        "runtime/tests/test_x.py",
    ):
        assert not included(path), path


# ---- agentsc-http-ready -------------------------------------------------------------------


class Handler(http.server.BaseHTTPRequestHandler):
    status = 200
    hosts: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        Handler.hosts.append(self.headers.get("Host", ""))
        self.send_response(Handler.status if self.path == "/api/v1/readyz" else 404)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[int]:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    Handler.hosts = []
    Handler.status = 200
    yield httpd.server_address[1]
    httpd.shutdown()


def probe(*args: str) -> int:
    return subprocess.run(["bash", str(PROBE), *args], capture_output=True, check=False, timeout=20).returncode


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
def test_http_probe_sends_host_localhost_and_needs_200(server: int) -> None:
    assert probe(str(server), "/api/v1/readyz") == 0
    assert Handler.hosts == ["localhost"], "embassy's Host check always admits localhost"
    Handler.status = 503
    assert probe(str(server), "/api/v1/readyz") != 0
    Handler.status = 200
    assert probe(str(server), "/elsewhere") != 0


def test_http_probe_fails_on_closed_port_and_bad_arguments() -> None:
    assert probe("1", "/api/v1/readyz") != 0
    assert probe("80; id", "/x") == 2
    assert probe("8080", "no-slash") == 2


# ---- release workflow ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(RELEASE.read_text())


def steps(workflow: dict) -> Iterator[tuple[str, dict]]:
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            yield job_name, step


def test_release_runs_on_version_tags_only(workflow: dict) -> None:
    # PyYAML reads the key `on` as True (YAML 1.1)
    trigger = workflow.get("on", workflow.get(True))
    assert trigger == {"push": {"tags": ["v*"]}}
    assert workflow["permissions"] == {}


def test_actions_are_pinned_to_commit_shas() -> None:
    uses = re.findall(r"uses:\s*(\S+)(.*)", RELEASE.read_text())
    assert uses
    for ref, comment in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref
        assert re.search(r"# v\d+\.\d+\.\d+", comment), f"{ref}: name the tag in a comment"


def test_binaries_cover_the_three_targets(workflow: dict) -> None:
    matrix = workflow["jobs"]["binaries"]["strategy"]["matrix"]["include"]
    assert {m["target"] for m in matrix} == {
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
    }
    build = next(s for _, s in steps(workflow) if s.get("name") == "Build")["run"]
    for crate in ("agentscd", "agentsc-cli", "embassy"):
        assert f"-p {crate}" in build
    assert "cargo zigbuild" in build
    package = next(s for _, s in steps(workflow) if s.get("name") == "Package")["run"]
    assert "for bin in agentscd agentsc embassy" in package


def test_images_are_multi_arch_on_ghcr(workflow: dict) -> None:
    job = workflow["jobs"]["images"]
    assert job["permissions"] == {"contents": "read", "packages": "write"}
    assert job["strategy"]["matrix"]["image"] == ["agentscd", "embassy"]
    assert workflow["env"]["IMAGE_PREFIX"] == "ghcr.io/f8fvwgzc/agent-sidecar"
    push = next(s for s in job["steps"] if s.get("uses", "").startswith("docker/build-push-action@"))
    w = push["with"]
    assert w["file"] == "docker/Dockerfile"
    assert w["context"] == "."
    assert w["target"] == "${{ matrix.image }}"
    assert w["platforms"] == "linux/amd64,linux/arm64"
    assert w["build-args"] == "BINARIES=prebuilt"
    assert w["push"] is True
    meta = next(s for s in job["steps"] if s.get("id") == "meta")
    assert meta["with"]["images"] == "${{ env.IMAGE_PREFIX }}/${{ matrix.image }}"


def test_release_builds_nothing_before_the_packaging_checks_pass(workflow: dict) -> None:
    job = workflow["jobs"]["packaging"]
    assert job["needs"] == "version"
    assert job["permissions"] == {"contents": "read"}
    run = "\n".join(s.get("run", "") for s in job["steps"])
    assert "make packaging-test" in run
    # the tools whose tests would otherwise be skipped must be present
    for tool in ("helm version", "docker compose version", "shellcheck --version"):
        assert tool in run
    assert set(workflow["jobs"]["binaries"]["needs"]) == {"version", "packaging"}
    # images and the release need binaries, so they wait for the checks too
    for name in ("images", "release"):
        assert "binaries" in workflow["jobs"][name]["needs"]
    # same uv as the agentscd image
    [uv_image] = re.findall(r"ghcr\.io/astral-sh/uv:(\S+)", DOCKERFILE.read_text())
    assert workflow["env"]["UV_VERSION"] == uv_image


def test_release_publishes_binaries_and_checksums(workflow: dict) -> None:
    job = workflow["jobs"]["release"]
    assert job["permissions"] == {"contents": "write"}
    assert set(job["needs"]) == {"version", "binaries", "images"}
    run = "\n".join(s.get("run", "") for s in job["steps"])
    assert "sha256sum -- *.tar.gz >SHA256SUMS" in run
    assert "gh release create" in run and "dist/SHA256SUMS" in run
    for name, j in workflow["jobs"].items():
        if name != "release":
            assert j["permissions"].get("contents") == "read", name


def test_release_publishes_the_image_digests(workflow: dict, tmp_path: Path) -> None:
    # the chart's sidecar image allow-list (images.agentscd.digest) takes these digests
    images = workflow["jobs"]["images"]["steps"]
    push = next(s for s in images if s.get("uses", "").startswith("docker/build-push-action@"))
    record = next(s for s in images if s.get("name") == "Record the image digest")
    assert push["id"] == "push"
    assert record["env"]["DIGEST"] == "${{ steps.push.outputs.digest }}"
    assert record["env"]["IMAGE"] == "${{ env.IMAGE_PREFIX }}/${{ matrix.image }}"
    upload = next(s for s in images if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "digest-${{ matrix.image }}"
    # the step itself: one `<image>@<digest>` line, and no line without a digest
    for digest, ok in (("sha256:" + "a" * 64, True), ("", False), ("sha256:short", False)):
        r = subprocess.run(
            ["bash", "-eo", "pipefail", "-c", record["run"]],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin", "IMAGE": "ghcr.io/x/agentscd", "DIGEST": digest, "NAME": "agentscd"},
            capture_output=True,
            text=True,
            check=False,
        )
        assert (r.returncode == 0) == ok, r.stdout + r.stderr
        if ok:
            assert (tmp_path / "digests/agentscd").read_text() == f"ghcr.io/x/agentscd@{digest}\n"
    release = workflow["jobs"]["release"]["steps"]
    download = [s for s in release if s.get("uses", "").startswith("actions/download-artifact@")]
    assert {s["with"]["pattern"] for s in download} == {"binaries-*", "digest-*"}
    run = "\n".join(s.get("run", "") for s in release)
    assert "cat digests/agentscd digests/embassy >dist/IMAGE_DIGESTS" in run
    assert "dist/SHA256SUMS dist/IMAGE_DIGESTS" in run


@pytest.mark.parametrize(
    ("tag", "crate", "chart", "ok"),
    [
        ("v0.2.0", "0.2.0", "0.2.0", True),
        ("v0.3.0-rc.1", "0.3.0-rc.1", "0.3.0-rc.1", True),
        ("v0.2.0", "0.1.0", "0.2.0", False),
        ("v0.2.0", "0.2.0", "0.1.0", False),
        ("v0.2", "0.2", "0.2", False),
        ("v0.2.0;id", "0.2.0", "0.2.0", False),
    ],
)
def test_release_tag_must_match_crate_and_chart_versions(
    workflow: dict, tmp_path: Path, tag: str, crate: str, chart: str, ok: bool
) -> None:
    step = next(s for s in workflow["jobs"]["version"]["steps"] if s.get("id") == "version")
    (tmp_path / "Cargo.toml").write_text(
        f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{crate}"\nedition = "2024"\n\n'
        '[workspace.dependencies]\nversion = "9.9.9"\n'
    )
    chart_dir = tmp_path / "deploy/helm/agent-sidecar"
    chart_dir.mkdir(parents=True)
    (chart_dir / "Chart.yaml").write_text(f'apiVersion: v2\nversion: 9.9.9\nappVersion: "{chart}"\n')
    output = tmp_path / "github_output"
    r = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "TAG": tag, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        check=False,
    )
    if ok:
        assert r.returncode == 0, r.stdout + r.stderr
        assert output.read_text() == f"version={tag[1:]}\n"
    else:
        assert r.returncode != 0
        assert "::error::" in r.stdout
