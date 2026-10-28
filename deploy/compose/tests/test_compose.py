"""Tests of the Docker Compose stack (docs/design/agent-platform.md §14).

Run with `make packaging-test`. `gen-env.sh` runs against a stand-in for `embassy token
create` (and against the real binary when EMBASSY_BIN is set); `docker compose config`
renders the stack with a generated .env (skipped without docker compose).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_DIR = ROOT / "deploy/compose"
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"
GEN_ENV = COMPOSE_DIR / "gen-env.sh"
SERVICES = ("orders", "inventory")

# `embassy serve` (design §8.1) and `agentscd` (design §6.1 plus CONTRACT.md §2) flags.
SERVE_FLAGS = {
    "components",
    "http-addr",
    "grpc-addr",
    "webhook-addr",
    "ca-dir",
    "ca-secret",
    "tls-secret",
    "tls-dir",
    "store",
    "config",
    "dns-name",
    "http-tls",
    "auto-adopt",
    "webhook-config-name",
    "validating-webhook-name",
    "injector-image",
    "cp-namespace",
    "ui-dir",
    "dev",
}
SIDECAR_FLAGS = {
    "control-plane",
    "ca-address",
    "service",
    "namespace",
    "app-port",
    "pod-name",
    "ca-file",
    "k8s-token-file",
    "join-token-file",
    "state-dir",
    "app-token-file",
    "peer-address-template",
    "otlp-endpoint-allow",
    "charter",
    "tls-dir",
    "http-addr",
    "grpc-addr",
    "mesh-addr",
    "socket-dir",
    "runtime-cmd",
    "no-runtime",
}

# Stands in for `embassy token create`: the same output shape (token, comment, YAML entry).
FAKE_EMBASSY = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import base64, hashlib, os, secrets, sys
    args = sys.argv[1:]
    assert args[:2] == ["token", "create"], args
    opts, i = {}, 2
    while i < len(args):
        if args[i] in ("--join", "--payloads"):
            opts[args[i]] = True
            i += 1
        else:
            opts[args[i]] = args[i + 1]
            i += 2
    token = "att_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    sha = hashlib.sha256(token.encode()).hexdigest()
    if os.environ.get("FAKE_BAD_HASH"):
        sha = "0" * 64
    with open(os.environ["FAKE_LOG"], "a") as log:
        log.write(" ".join(args) + "\\n")
    print(token)
    print("# The token above is shown only once. Add this entry to the ControlPlaneConfig x:")
    print(f"- name: {opts['--name']}")
    if "--join" in opts:
        print(f"  sha256: {sha}")
        print(f"  namespace: {opts['--namespace']}")
        print("  services:")
        print(f"  - {opts['--services']}")
        print("  expires_at: 2027-10-21T10:00:00Z")
    else:
        print(f"  role: {opts.get('--role', 'viewer')}")
        print(f"  sha256: {sha}")
        print("  namespaces:")
        print("  - '*'")
        print(f"  payloads: {'true' if '--payloads' in opts else 'false'}")
    """
)

needs_compose = pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(["docker", "compose", "version"], capture_output=True, check=False).returncode != 0,
    reason="docker compose is not installed",
)


def read_env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key] = value
    return out


def run_gen_env(env_file: Path, embassy: str, **extra: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "SERVICES"}
    env.update({"EMBASSY": embassy, **extra})
    return subprocess.run([str(GEN_ENV), str(env_file)], capture_output=True, text=True, env=env, check=False)


@pytest.fixture
def fake_embassy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, Path]:
    script = tmp_path / "fake-embassy"
    script.write_text(FAKE_EMBASSY)
    script.chmod(0o755)
    log = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_LOG", str(log))
    return str(script), log


def check_env(env: dict[str, str]) -> None:
    token = re.compile(r"att_[A-Za-z0-9_-]{43}")
    assert "AGENTSC_NAMESPACE" not in env, "the namespace is fixed, not a setting"
    names = ["AGENTSC_ADMIN_TOKEN"] + [f"AGENTSC_JOIN_TOKEN_{s.upper()}" for s in SERVICES]
    for name in names:
        assert token.fullmatch(env[name]), name
        assert env[f"{name}_SHA256"] == hashlib.sha256(env[name].encode()).hexdigest()
    for s in SERVICES:
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", env[f"AGENTSC_JOIN_TOKEN_{s.upper()}_EXPIRES_AT"])
    assert len({env[n] for n in names}) == len(names), "every token is different"


# ---- gen-env.sh ---------------------------------------------------------------------------


def test_gen_env_writes_tokens_once_with_mode_0600(tmp_path: Path, fake_embassy: tuple[str, Path]) -> None:
    embassy, log = fake_embassy
    env_file = tmp_path / ".env"
    # AGENTSC_NAMESPACE in the environment changes nothing: the example charters fix agentsc-demo
    r = run_gen_env(env_file, embassy, AGENTSC_NAMESPACE="shop")
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    env = read_env(env_file)
    check_env(env)
    assert env["AGENTSC_ADMIN_TOKEN"] in r.stdout, "the admin token is printed once"
    for s in SERVICES:
        assert env[f"AGENTSC_JOIN_TOKEN_{s.upper()}"] not in r.stdout
    calls = log.read_text().splitlines()
    assert calls == [
        "token create --name compose-admin --role admin --payloads",
        "token create --name compose-orders --join --namespace agentsc-demo --services orders --expires-in 8760h",
        "token create --name compose-inventory --join --namespace agentsc-demo --services inventory --expires-in 8760h",
    ]

    before = env_file.read_bytes()
    again = run_gen_env(env_file, embassy)
    assert again.returncode == 0, again.stderr
    assert env_file.read_bytes() == before, "an existing .env is kept"
    assert "keeping" in again.stdout
    assert len(log.read_text().splitlines()) == 3, "no new tokens"


def test_gen_env_refuses_a_hash_that_is_not_the_tokens(tmp_path: Path, fake_embassy: tuple[str, Path]) -> None:
    embassy, _ = fake_embassy
    env_file = tmp_path / ".env"
    r = run_gen_env(env_file, embassy, FAKE_BAD_HASH="1")
    assert r.returncode != 0
    assert "sha256" in r.stderr
    assert not env_file.exists()
    assert list(tmp_path.glob(".env.*")) == [], "no temporary file is left behind"


def test_gen_env_with_the_real_embassy(tmp_path: Path) -> None:
    binary = os.environ.get("EMBASSY_BIN")
    if not binary or not Path(binary).exists():
        pytest.skip("EMBASSY_BIN is not set (make packaging-test builds and sets it)")
    env_file = tmp_path / ".env"
    r = run_gen_env(env_file, str(Path(binary).resolve()))
    assert r.returncode == 0, r.stderr
    check_env(read_env(env_file))


# ---- docker compose config ----------------------------------------------------------------


@pytest.fixture(scope="module")
def sample_env() -> dict[str, str]:
    """A .env shaped like gen-env.sh's, with random tokens that are never used."""
    env = {}
    for name in ["AGENTSC_ADMIN_TOKEN"] + [f"AGENTSC_JOIN_TOKEN_{s.upper()}" for s in SERVICES]:
        token = "att_" + secrets.token_urlsafe(32)
        env[name] = token
        env[f"{name}_SHA256"] = hashlib.sha256(token.encode()).hexdigest()
    for s in SERVICES:
        env[f"AGENTSC_JOIN_TOKEN_{s.upper()}_EXPIRES_AT"] = "2027-10-21T10:00:00Z"
    return env


def compose_config(env_file: Path) -> subprocess.CompletedProcess[str]:
    # --env-file replaces deploy/compose/.env, which may exist after `make compose-up`.
    args = ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(env_file)]
    clean = {k: v for k, v in os.environ.items() if not k.startswith("AGENTSC_")}
    clean.pop("ANTHROPIC_API_KEY", None)
    return subprocess.run(
        [*args, "config", "--format", "json"],
        capture_output=True,
        text=True,
        env=clean,
        cwd=ROOT,
        check=False,
    )


@pytest.fixture(scope="module")
def stack(sample_env: dict[str, str], tmp_path_factory: pytest.TempPathFactory) -> dict:
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    env_file = tmp_path_factory.mktemp("compose") / ".env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in sample_env.items()))
    r = compose_config(env_file)
    if r.returncode != 0 and "is not a docker command" in r.stderr:
        pytest.skip("docker compose is not installed")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def split_flags(command: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for a in command:
        m = re.fullmatch(r"--([a-z][a-z0-9-]*)(?:=(.*))?", a)
        assert m, f"argument {a!r} is not --flag[=value]"
        out.setdefault(m.group(1), []).append(m.group(2) or "")
    return out


@needs_compose
def test_stack_has_the_designed_services(stack: dict) -> None:
    assert set(stack["services"]) == {
        "embassy",
        "orders-sidecar",
        "orders",
        "inventory-sidecar",
        "inventory",
        "otel-collector",
        "jaeger",
    }
    assert stack["name"] == "agentsc"


@needs_compose
def test_missing_env_is_a_clear_error(tmp_path: Path) -> None:
    empty = tmp_path / ".env"
    empty.write_text("")
    r = compose_config(empty)
    assert r.returncode != 0
    assert "make compose-up" in r.stderr


@needs_compose
def test_embassy_runs_every_component_with_the_file_store(stack: dict) -> None:
    svc = stack["services"]["embassy"]
    assert svc["command"][0] == "serve"
    flags = split_flags(svc["command"][1:])
    assert "components" not in flags, "default: all components"
    assert "dev" not in flags
    assert flags["auto-adopt"] == [""]
    assert flags["store"] == ["file:/var/lib/agentsc/store"]
    assert flags["ca-dir"] == ["/var/lib/agentsc/ca"]
    assert flags["http-addr"] == ["0.0.0.0:8080"]
    assert flags["grpc-addr"] == ["0.0.0.0:15012"]
    assert flags["config"] == ["/etc/agentsc/config.yaml"]
    assert set(flags) <= SERVE_FLAGS, set(flags) - SERVE_FLAGS
    assert svc["build"]["dockerfile"] == "docker/Dockerfile"
    assert svc["build"]["target"] == "embassy"
    assert Path(svc["build"]["context"]).resolve() == ROOT
    assert [(p["host_ip"], p["published"], p["target"]) for p in svc["ports"]] == [("127.0.0.1", "8080", 8080)]
    assert svc["configs"] == [{"source": "control-plane", "target": "/etc/agentsc/config.yaml"}]
    assert "depends_on" not in svc
    assert svc["healthcheck"]["test"] == ["CMD", "agentsc-http-ready", "8080", "/api/v1/readyz"]
    assert {v["source"]: v["target"] for v in svc["volumes"]} == {
        "embassy-data": "/var/lib/agentsc",
        "agentsc-ca": "/agentsc-ca",
    }

    binary = os.environ.get("EMBASSY_BIN")
    if binary and Path(binary).exists():
        help_text = subprocess.run([binary, "serve", "--help"], capture_output=True, text=True, check=True).stdout
        assert set(flags) <= set(re.findall(r"--([a-z][a-z0-9-]+)", help_text))


# Stands in for embassy in the entrypoint test: `ca-init --out <dir>` writes a CA there, anything
# else is logged (that is where `serve ...` would run).
FAKE_EMBASSY_CA = textwrap.dedent(
    """\
    #!/bin/sh
    set -e
    if [ "$1" = ca-init ]; then
      mkdir -p "$3"
      echo CERT >"$3/ca.crt"
      echo KEY >"$3/ca.key"
      echo ca-init >>"$FAKE_LOG"
    else
      echo "$*" >>"$FAKE_LOG"
    fi
    """
)


def run_entrypoint(entrypoint: list[str], command: list[str], data: Path, public: Path, bin_dir: Path) -> None:
    # `docker compose config` writes $ as $$; the shell in the container sees one $.
    _shell, flag, script, name = entrypoint
    script = script.replace("$$", "$").replace("/var/lib/agentsc", str(data)).replace("/agentsc-ca", str(public))
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    subprocess.run(["sh", flag, script, name, *command], env=env, check=True)


@needs_compose
def test_embassy_publishes_only_the_ca_certificate_then_serves(
    stack: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    svc = stack["services"]["embassy"]
    entrypoint = svc["entrypoint"]
    assert entrypoint[:2] == ["/bin/sh", "-ec"] and entrypoint[3] == "embassy"
    # the CA is created in the --ca-dir that serve reads
    assert "embassy ca-init --out /var/lib/agentsc/ca" in entrypoint[2]
    assert split_flags(svc["command"][1:])["ca-dir"] == ["/var/lib/agentsc/ca"]

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "embassy"
    fake.write_text(FAKE_EMBASSY_CA)
    fake.chmod(0o755)
    log = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_LOG", str(log))
    data, public = tmp_path / "data", tmp_path / "public"
    data.mkdir(mode=0o700)
    public.mkdir()

    run_entrypoint(entrypoint, svc["command"], data, public, bin_dir)
    assert sorted(p.name for p in public.iterdir()) == ["ca.crt"], "only the certificate is published"
    assert (public / "ca.crt").read_bytes() == (data / "ca/ca.crt").read_bytes()
    assert stat.S_IMODE((public / "ca.crt").stat().st_mode) == 0o644
    assert stat.S_IMODE((data / "ca/ca.key").stat().st_mode) == 0o600
    assert log.read_text().splitlines() == ["ca-init", " ".join(svc["command"])]

    # a restart keeps the CA and publishes its (possibly changed) certificate again
    (data / "ca/ca.crt").write_text("ROTATED\n")
    run_entrypoint(entrypoint, svc["command"], data, public, bin_dir)
    assert (public / "ca.crt").read_text() == "ROTATED\n"
    assert log.read_text().splitlines().count("ca-init") == 1

    for name, other in stack["services"].items():
        for v in other.get("volumes", []):
            if v.get("source") == "embassy-data":
                assert name == "embassy", f"{name} must not see the CA key"
            if v.get("source") == "agentsc-ca" and name != "embassy":
                assert v["read_only"] is True, f"{name} mounts agentsc-ca writable"


@needs_compose
def test_control_plane_config_holds_only_hashes(stack: dict, sample_env: dict[str, str]) -> None:
    content = stack["configs"]["control-plane"]["content"]
    for name, value in sample_env.items():
        if re.fullmatch(r"AGENTSC_(ADMIN|JOIN)_TOKEN(_[A-Z]+)?", name):
            assert value not in content, f"{name} leaked into the config"
    cfg = yaml.safe_load(content)
    assert cfg["apiVersion"] == "agentsc.io/v1alpha1"
    assert cfg["kind"] == "ControlPlaneConfig"
    assert cfg["auth"]["anonymous"] == "none"
    [admin] = cfg["auth"]["tokens"]
    assert admin == {
        "name": "compose-admin",
        "role": "admin",
        "sha256": sample_env["AGENTSC_ADMIN_TOKEN_SHA256"],
        "namespaces": ["*"],
        "payloads": True,
    }
    assert cfg["issuance"]["kubernetes"] is False
    joins = {j["services"][0]: j for j in cfg["issuance"]["join_tokens"]}
    assert set(joins) == set(SERVICES)
    for s in SERVICES:
        assert joins[s] == {
            "name": f"compose-{s}",
            "sha256": sample_env[f"AGENTSC_JOIN_TOKEN_{s.upper()}_SHA256"],
            "namespace": yaml.safe_load((ROOT / f"examples/charters/{s}.charter.yaml").read_text())["service"][
                "namespace"
            ],
            "services": [s],
            "expires_at": "2027-10-21T10:00:00Z",
        }


@needs_compose
@pytest.mark.parametrize("service", SERVICES)
def test_sidecar_owns_the_network_namespace_and_joins_the_control_plane(stack: dict, service: str) -> None:
    sidecar = stack["services"][f"{service}-sidecar"]
    app = stack["services"][service]
    charter = yaml.safe_load((ROOT / f"examples/charters/{service}.charter.yaml").read_text())
    flags = split_flags(sidecar["command"])
    assert set(flags) <= SIDECAR_FLAGS, set(flags) - SIDECAR_FLAGS
    assert flags["control-plane"] == ["embassy:15012"]
    assert flags["ca-file"] == ["/agentsc-ca/ca.crt"]
    assert flags["join-token-file"] == [f"/run/secrets/{service}-join-token"]
    assert flags["peer-address-template"] == ["{service}-sidecar:{port}"]
    assert flags["service"] == [service]
    assert flags["namespace"] == [charter["service"]["namespace"]]
    assert flags["app-port"] == [str(charter["service"]["app_port"])]
    assert flags["charter"] == ["/etc/agentsc/charter/charter.yaml"]
    assert sidecar["image"] == "agentsc/agentscd:dev"
    assert sidecar["environment"]["OTEL_EXPORTER_OTLP_ENDPOINT"] == "http://otel-collector:4318"
    assert sidecar["depends_on"]["embassy"]["condition"] == "service_healthy"
    assert sidecar["secrets"] == [{"source": f"{service}-join-token", "target": f"/run/secrets/{service}-join-token"}]
    secret = stack["secrets"][f"{service}-join-token"]
    assert secret["environment"] == f"AGENTSC_JOIN_TOKEN_{service.upper()}"
    mounts = {v["target"]: v for v in sidecar["volumes"]}
    assert mounts["/agentsc-ca"]["source"] == "agentsc-ca" and mounts["/agentsc-ca"]["read_only"] is True
    charter_mount = mounts["/etc/agentsc/charter/charter.yaml"]
    assert Path(charter_mount["source"]) == ROOT / f"examples/charters/{service}.charter.yaml"
    assert charter_mount["read_only"] is True
    assert mounts["/run/agentsc/state"]["source"] == f"{service}-state"
    assert "50002" in sidecar["expose"]
    assert sidecar["healthcheck"]["test"] == ["CMD", "agentsc-ready"]

    assert app["network_mode"] == f"service:{service}-sidecar"
    assert app["depends_on"][f"{service}-sidecar"]["restart"] is True
    assert "ports" not in app, "the sidecar publishes ports for the shared namespace"


@needs_compose
def test_only_localhost_ports_are_published(stack: dict) -> None:
    published = {}
    for name, svc in stack["services"].items():
        for p in svc.get("ports", []):
            assert p["host_ip"] == "127.0.0.1", f"{name} publishes {p} beyond localhost"
            published[p["published"]] = (name, p["target"])
    assert published == {
        "8080": ("embassy", 8080),
        "8081": ("orders-sidecar", 8080),
        "16686": ("jaeger", 16686),
    }


@needs_compose
def test_traces_flow_to_jaeger(stack: dict) -> None:
    collector = stack["services"]["otel-collector"]
    assert collector["image"].startswith("otel/opentelemetry-collector:")
    assert collector["configs"] == [{"source": "otel-collector", "target": "/etc/otelcol/config.yaml"}]
    assert stack["services"]["jaeger"]["image"].startswith("jaegertracing/jaeger:")
    for svc in stack["services"].values():
        assert not svc["image"].endswith(":latest")


def test_collector_config_receives_otlp_http_and_exports_to_jaeger() -> None:
    cfg = yaml.safe_load((COMPOSE_DIR / "otel-collector.yaml").read_text())
    assert cfg["receivers"]["otlp"]["protocols"]["http"]["endpoint"] == "0.0.0.0:4318"
    traces = cfg["service"]["pipelines"]["traces"]
    assert traces["receivers"] == ["otlp"]
    [exporter] = traces["exporters"]
    assert exporter.startswith("otlp_grpc/")
    assert cfg["exporters"][exporter]["endpoint"] == "jaeger:4317"
    assert cfg["service"]["pipelines"]["metrics"]["receivers"] == ["otlp"]


def test_namespace_is_fixed_to_the_example_charters() -> None:
    # The sidecars' --namespace is authoritative and the mounted start-up charters name agentsc-demo
    # (service.namespace, inventory's authz identity for orders): it cannot be a setting.
    for s in SERVICES:
        charter = yaml.safe_load((ROOT / f"examples/charters/{s}.charter.yaml").read_text())
        assert charter["service"]["namespace"] == "agentsc-demo"
    assert "AGENTSC_NAMESPACE" not in COMPOSE_FILE.read_text()
    assert "AGENTSC_NAMESPACE" not in GEN_ENV.read_text()
    assert "NAMESPACE=agentsc-demo\n" in GEN_ENV.read_text()


def test_env_file_is_git_ignored() -> None:
    assert ".env" in (COMPOSE_DIR / ".gitignore").read_text().split()
