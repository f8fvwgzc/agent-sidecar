"""Tests of the agent-sidecar Helm chart (docs/design/agent-platform.md §13).

Run with `make packaging-test`. They render the chart with `helm template` (skipped when
helm is not installed) and check the resources against the design: RBAC, webhooks, the
CRD link, both Deployments and their embassy flags, the injection template, Secrets,
Services and NetworkPolicy.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/agent-sidecar"
CRD_FILE = ROOT / "deploy/crds/charters.attache.io.yaml"
CHART_CRD_FILE = CHART / "files/crds/charters.attache.io.yaml"
DEMO_APPS = ROOT / "deploy/helm/demo/apps.yaml"
DEMO_SCRIPT = ROOT / "deploy/helm/demo.sh"
README = CHART / "README.md"
NS = "attache-system"

# `embassy serve` flags (design §8.1).
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

needs_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")


def helm(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["helm", *args], capture_output=True, text=True, check=False)


def render(*args: str, kube_version: str = "1.29.0") -> list[dict]:
    r = helm(
        "template",
        "agent-sidecar",
        str(CHART),
        "--namespace",
        NS,
        "--kube-version",
        kube_version,
        *args,
    )
    assert r.returncode == 0, r.stderr
    return [d for d in yaml.safe_load_all(r.stdout) if d]


def render_fails(*args: str) -> str:
    r = helm("template", "agent-sidecar", str(CHART), "--namespace", NS, *args)
    assert r.returncode != 0, f"helm template {args} should fail"
    return r.stderr


def find(docs: list[dict], kind: str, name: str) -> dict:
    found = [d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name]
    assert len(found) == 1, f"{kind}/{name}: found {len(found)}"
    return found[0]


def kinds(docs: list[dict]) -> set[tuple[str, str]]:
    return {(d["kind"], d["metadata"]["name"]) for d in docs}


def container(deployment: dict) -> dict:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1
    return containers[0]


def parse_args(args: list[str]) -> tuple[str, dict[str, list[str]]]:
    """`serve --a=1 --b` -> ("serve", {"a": ["1"], "b": [""]})."""
    sub, rest = args[0], args[1:]
    out: dict[str, list[str]] = {}
    for a in rest:
        m = re.fullmatch(r"--([a-z][a-z-]*)(?:=(.*))?", a)
        assert m, f"argument {a!r} is not --flag[=value]"
        out.setdefault(m.group(1), []).append(m.group(2) or "")
    return sub, out


def deployment_flags(docs: list[dict], name: str) -> dict[str, list[str]]:
    sub, flags = parse_args(container(find(docs, "Deployment", name))["args"])
    assert sub == "serve"
    return flags


def env(c: dict) -> dict[str, str]:
    return {e["name"]: e.get("value") for e in c.get("env", [])}


@pytest.fixture(scope="module")
def default() -> list[dict]:
    return render()


@pytest.fixture(scope="module")
def full() -> list[dict]:
    return render("-f", str(CHART / "ci/full-values.yaml"))


# ---- chart as a whole --------------------------------------------------------------------


@needs_helm
@pytest.mark.parametrize("values", [None, *sorted((CHART / "ci").glob("*-values.yaml"))])
def test_lint_passes_strict(values: Path | None) -> None:
    args = ["lint", "--strict", str(CHART)] + (["-f", str(values)] if values else [])
    r = helm(*args)
    assert r.returncode == 0, r.stdout + r.stderr


@needs_helm
def test_kubernetes_1_29_is_the_floor() -> None:
    assert "kubeVersion" in render_fails("--kube-version", "1.28.9")
    render(kube_version="1.29.0")


@needs_helm
def test_default_render_has_exactly_the_designed_resources(default: list[dict]) -> None:
    assert kinds(default) == {
        ("CustomResourceDefinition", "charters.attache.io"),
        ("ServiceAccount", "embassy-ca"),
        ("ServiceAccount", "embassy"),
        ("ClusterRole", "attache-embassy"),
        ("ClusterRoleBinding", "attache-embassy"),
        ("Role", "attache-embassy-secrets"),
        ("RoleBinding", "attache-embassy-secrets"),
        ("ClusterRole", "attache-charter-view"),
        ("ClusterRole", "attache-charter-edit"),
        ("Secret", "embassy-config"),
        ("Secret", "attache-session-key"),
        ("Deployment", "embassy-ca"),
        ("PodDisruptionBudget", "embassy-ca"),
        ("Deployment", "embassy"),
        ("Service", "embassy-ca"),
        ("Service", "embassy"),
        ("MutatingWebhookConfiguration", "attache-sidecar-injector"),
        ("ValidatingWebhookConfiguration", "attache-charter-validator"),
    }
    for d in default:
        if d["kind"] not in {
            "CustomResourceDefinition",
            "ClusterRole",
            "ClusterRoleBinding",
            "MutatingWebhookConfiguration",
            "ValidatingWebhookConfiguration",
        }:
            assert d["metadata"]["namespace"] == NS, d["metadata"]


# ---- CRD ----------------------------------------------------------------------------------


def test_chart_crd_is_a_link_to_deploy_crds() -> None:
    # A link, not a copy: the chart cannot drift from the generated CRD.
    assert CHART_CRD_FILE.is_symlink(), f"{CHART_CRD_FILE} must be a symbolic link to {CRD_FILE}"
    assert os.readlink(CHART_CRD_FILE) == "../../../../crds/charters.attache.io.yaml"
    assert CHART_CRD_FILE.resolve() == CRD_FILE.resolve()


@needs_helm
def test_crd_is_rendered_unchanged_and_kept_on_uninstall(default: list[dict]) -> None:
    rendered = find(default, "CustomResourceDefinition", "charters.attache.io")
    source = yaml.safe_load(CRD_FILE.read_text())
    assert rendered["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert rendered["metadata"]["labels"]["app.kubernetes.io/part-of"] == "attache"
    for doc in (rendered, source):
        doc["metadata"].pop("annotations", None)
        doc["metadata"].pop("labels", None)
    assert rendered == source
    version = rendered["spec"]["versions"][0]
    assert version["subresources"] == {"status": {}}
    columns = [c["name"] for c in version["additionalPrinterColumns"]]
    assert columns == ["Service", "Version", "Valid", "Synced", "Age"]


@needs_helm
def test_crds_install_false_leaves_the_crd_out() -> None:
    docs = render("--set", "crds.install=false")
    assert not [d for d in docs if d["kind"] == "CustomResourceDefinition"]


# ---- RBAC ---------------------------------------------------------------------------------


def norm(rules: list[dict]) -> list[tuple]:
    return sorted(
        (
            tuple(r.get("apiGroups", [])),
            tuple(r.get("resources", [])),
            tuple(r.get("resourceNames", [])),
            tuple(sorted(r["verbs"])),
        )
        for r in rules
    )


@needs_helm
def test_cluster_role_is_the_design_plus_charter_delete(default: list[dict]) -> None:
    role = find(default, "ClusterRole", "attache-embassy")
    webhooks = ("attache-sidecar-injector", "attache-charter-validator")
    assert norm(role["rules"]) == norm(
        [
            {
                "apiGroups": ["attache.io"],
                "resources": ["charters"],
                # §13 plus delete: DELETE /services/{ns}/{svc} (§10) deletes the Charter
                "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
            },
            {
                "apiGroups": ["attache.io"],
                "resources": ["charters/status"],
                "verbs": ["get", "update", "patch"],
            },
            {
                "apiGroups": ["apps"],
                "resources": ["controllerrevisions"],
                "verbs": ["get", "list", "create", "delete"],
            },
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
            {
                "apiGroups": ["authentication.k8s.io"],
                "resources": ["tokenreviews"],
                "verbs": ["create"],
            },
            {
                "apiGroups": ["admissionregistration.k8s.io"],
                "resources": [
                    "mutatingwebhookconfigurations",
                    "validatingwebhookconfigurations",
                ],
                "resourceNames": list(webhooks),
                "verbs": ["get", "watch", "patch"],
            },
        ]
    )
    binding = find(default, "ClusterRoleBinding", "attache-embassy")
    assert binding["roleRef"]["name"] == "attache-embassy"
    assert {(s["name"], s["namespace"]) for s in binding["subjects"]} == {
        ("embassy-ca", NS),
        ("embassy", NS),
    }


@needs_helm
def test_only_embassy_ca_can_read_the_ca_and_tls_secrets(default: list[dict]) -> None:
    role = find(default, "Role", "attache-embassy-secrets")
    names = ["attache-ca", "embassy-tls", "attache-session-key"]
    assert norm(role["rules"]) == norm(
        [
            {
                "apiGroups": [""],
                "resources": ["secrets"],
                "resourceNames": names,
                "verbs": ["get", "update"],
            },
            # create cannot be restricted by name (documented in the template)
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]},
        ]
    )
    binding = find(default, "RoleBinding", "attache-embassy-secrets")
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "embassy-ca", "namespace": NS}]
    # embassy gets the serving certificate, config and session key only as mounted volumes
    embassy = find(default, "Deployment", "embassy")
    pod = embassy["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "embassy"
    secrets = {v["secret"]["secretName"] for v in pod["volumes"] if "secret" in v}
    assert secrets == {"embassy-config", "attache-session-key", "embassy-tls"}


@needs_helm
def test_no_configmap_permissions_anywhere(full: list[dict]) -> None:
    for d in full:
        if d["kind"] in {"Role", "ClusterRole"}:
            for rule in d["rules"]:
                assert "configmaps" not in rule.get("resources", []), d["metadata"]["name"]
                assert "*" not in rule.get("resources", []), d["metadata"]["name"]
                assert "*" not in rule["verbs"], d["metadata"]["name"]


@needs_helm
def test_existing_ca_secret_is_only_read(full: list[dict]) -> None:
    role = find(full, "Role", "attache-embassy-existing-ca")
    assert role["metadata"]["namespace"] == "attache-demo"
    assert role["rules"] == [
        {
            "apiGroups": [""],
            "resources": ["secrets"],
            "resourceNames": ["attache-ca"],
            "verbs": ["get"],
        }
    ]
    binding = find(full, "RoleBinding", "attache-embassy-existing-ca")
    assert binding["metadata"]["namespace"] == "attache-demo"
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "embassy-ca", "namespace": NS}]
    assert deployment_flags(full, "embassy-ca")["ca-secret"] == ["attache-demo/attache-ca"]


@needs_helm
def test_bad_existing_ca_secret_is_refused() -> None:
    assert "existingSecret" in render_fails("--set", "ca.existingSecret=attache-ca")


@needs_helm
def test_user_cluster_roles_aggregate(default: list[dict], full: list[dict]) -> None:
    view = find(default, "ClusterRole", "attache-charter-view")
    edit = find(default, "ClusterRole", "attache-charter-edit")
    agg = "rbac.authorization.k8s.io/aggregate-to-"
    assert {k for k in view["metadata"]["labels"] if k.startswith(agg)} == {
        agg + "view",
        agg + "edit",
        agg + "admin",
    }
    assert {k for k in edit["metadata"]["labels"] if k.startswith(agg)} == {agg + "admin"}
    for rule in view["rules"]:
        assert set(rule["verbs"]) == {"get", "list", "watch"}
    status_rules = [r for r in edit["rules"] if "charters/status" in r["resources"]]
    assert all(set(r["verbs"]) == {"get", "list", "watch"} for r in status_rules)
    full_edit = find(full, "ClusterRole", "attache-charter-edit")
    assert {k for k in full_edit["metadata"]["labels"] if k.startswith(agg)} == {
        agg + "admin",
        agg + "edit",
    }
    off = render("-f", str(CHART / "ci/no-crd-values.yaml"))
    for name in ("attache-charter-view", "attache-charter-edit"):
        labels = find(off, "ClusterRole", name)["metadata"]["labels"]
        assert not [k for k in labels if k.startswith(agg)]


# ---- webhooks -----------------------------------------------------------------------------


@needs_helm
def test_webhooks_never_carry_a_ca_bundle(default: list[dict], full: list[dict]) -> None:
    for docs in (default, full):
        assert "caBundle" not in json.dumps(docs)


@needs_helm
def test_mutating_webhook_follows_the_design(default: list[dict], full: list[dict]) -> None:
    cfg = find(default, "MutatingWebhookConfiguration", "attache-sidecar-injector")
    [hook] = cfg["webhooks"]
    assert hook["admissionReviewVersions"] == ["v1"]
    assert hook["sideEffects"] == "None"
    assert hook["timeoutSeconds"] == 5
    assert hook["reinvocationPolicy"] == "Never"
    assert hook["failurePolicy"] == "Fail"
    assert hook["clientConfig"] == {"service": {"name": "embassy-ca", "namespace": NS, "path": "/mutate", "port": 443}}
    assert hook["rules"] == [
        {
            "apiGroups": [""],
            "apiVersions": ["v1"],
            "operations": ["CREATE"],
            "resources": ["pods"],
            "scope": "Namespaced",
        }
    ]
    assert hook["objectSelector"] == {"matchLabels": {"attache.io/inject": "true"}}
    assert hook["namespaceSelector"] == {
        "matchExpressions": [
            {"key": "attache.io/injection", "operator": "In", "values": ["enabled"]},
            {
                "key": "kubernetes.io/metadata.name",
                "operator": "NotIn",
                "values": ["kube-system", NS],
            },
        ]
    }
    [full_hook] = find(full, "MutatingWebhookConfiguration", "attache-sidecar-injector")["webhooks"]
    assert full_hook["failurePolicy"] == "Ignore"


@needs_helm
def test_webhook_entry_names_are_documented_for_the_ca_bundle_reconciler(default: list[dict]) -> None:
    readme = README.read_text()
    for kind, name, entry in (
        ("MutatingWebhookConfiguration", "attache-sidecar-injector", "sidecar-injector.attache.io"),
        ("ValidatingWebhookConfiguration", "attache-charter-validator", "charter-validator.attache.io"),
    ):
        assert [h["name"] for h in find(default, kind, name)["webhooks"]] == [entry]
        assert f"`{entry}`" in readme


@needs_helm
def test_validating_webhook_follows_the_design(default: list[dict]) -> None:
    cfg = find(default, "ValidatingWebhookConfiguration", "attache-charter-validator")
    [hook] = cfg["webhooks"]
    assert hook["failurePolicy"] == "Fail"
    assert hook["sideEffects"] == "None"
    assert hook["admissionReviewVersions"] == ["v1"]
    assert hook["clientConfig"]["service"] == {
        "name": "embassy-ca",
        "namespace": NS,
        "path": "/validate-charter",
        "port": 443,
    }
    assert hook["rules"] == [
        {
            "apiGroups": ["attache.io"],
            "apiVersions": ["v1alpha1"],
            "operations": ["CREATE", "UPDATE"],
            "resources": ["charters"],
            "scope": "Namespaced",
        }
    ]


# ---- Deployments --------------------------------------------------------------------------


@needs_helm
def test_embassy_ca_runs_ca_and_webhook_highly_available(default: list[dict]) -> None:
    dep = find(default, "Deployment", "embassy-ca")
    assert dep["spec"]["replicas"] == 2
    pod = dep["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "embassy-ca"
    [term] = pod["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"]
    assert term["podAffinityTerm"]["topologyKey"] == "kubernetes.io/hostname"
    selector = dep["spec"]["selector"]["matchLabels"]
    assert term["podAffinityTerm"]["labelSelector"]["matchLabels"] == selector
    pdb = find(default, "PodDisruptionBudget", "embassy-ca")
    assert pdb["spec"] == {"minAvailable": 1, "selector": {"matchLabels": selector}}

    flags = deployment_flags(default, "embassy-ca")
    assert flags["components"] == ["ca,webhook"]
    assert flags["grpc-addr"] == ["0.0.0.0:15012"]
    assert flags["webhook-addr"] == ["0.0.0.0:9443"]
    assert flags["ca-secret"] == [f"{NS}/attache-ca"]
    assert flags["tls-secret"] == [f"{NS}/embassy-tls"]
    assert flags["store"] == ["kubernetes"]
    assert flags["config"] == ["/etc/attache/config/config.yaml"]
    assert flags["webhook-config-name"] == ["attache-sidecar-injector"]
    assert flags["validating-webhook-name"] == ["attache-charter-validator"]
    assert flags["injector-image"] == ["ghcr.io/f8fvwgzc/agent-sidecar/attached:0.2.0"]
    assert flags["cp-namespace"] == [NS]
    # the webhook Service name must be in the serving certificate the API server checks
    assert f"embassy-ca.{NS}.svc" in flags["dns-name"]
    assert f"embassy.{NS}.svc" in flags["dns-name"]
    assert "dev" not in flags and "auto-adopt" not in flags

    c = container(dep)
    assert {p["name"]: p["containerPort"] for p in c["ports"]} == {"grpc": 15012, "webhook": 9443}
    mounts = {m["mountPath"] for m in c["volumeMounts"]}
    assert mounts == {"/etc/attache/config", "/tmp"}, "embassy-ca mounts no session key or CA"


@needs_helm
def test_embassy_ca_hard_anti_affinity_and_single_replica() -> None:
    docs = render("--set", "embassyCa.antiAffinity=hard")
    affinity = find(docs, "Deployment", "embassy-ca")["spec"]["template"]["spec"]["affinity"]
    assert "requiredDuringSchedulingIgnoredDuringExecution" in affinity["podAntiAffinity"]
    single = render("--set", "embassyCa.replicas=1")
    assert ("PodDisruptionBudget", "embassy-ca") not in kinds(single)


@needs_helm
def test_embassy_runs_one_replica_with_probes_on_the_api(default: list[dict]) -> None:
    dep = find(default, "Deployment", "embassy")
    assert dep["spec"]["replicas"] == 1
    assert dep["spec"]["strategy"] == {"type": "Recreate"}
    flags = deployment_flags(default, "embassy")
    assert flags["components"] == ["controlplane,api,ui"]
    assert flags["http-addr"] == ["0.0.0.0:8080"]
    assert flags["grpc-addr"] == ["0.0.0.0:15012"]
    assert flags["tls-dir"] == ["/etc/attache/tls"]
    assert flags["store"] == ["kubernetes"]
    assert flags["cp-namespace"] == [NS]
    assert set(flags["dns-name"]) == {
        "embassy",
        f"embassy.{NS}",
        f"embassy.{NS}.svc",
        f"embassy.{NS}.svc.cluster.local",
    }
    for absent in ("ca-dir", "ca-secret", "tls-secret", "dev", "auto-adopt", "http-tls"):
        assert absent not in flags

    c = container(dep)
    for probe, path in (("livenessProbe", "/api/v1/healthz"), ("readinessProbe", "/api/v1/readyz")):
        get = c[probe]["httpGet"]
        assert get["path"] == path
        assert get["port"] == "http"
        assert get["scheme"] == "HTTP"
        assert get["httpHeaders"] == [{"name": "Host", "value": "localhost"}]
    assert c["resources"] == {
        "requests": {"cpu": "100m", "memory": "256Mi"},
        "limits": {"memory": "1Gi"},
    }
    assert {p["name"]: p["containerPort"] for p in c["ports"]} == {"http": 8080, "grpc": 15012}
    mounts = {m["name"]: m["mountPath"] for m in c["volumeMounts"]}
    assert mounts["tls"] == "/etc/attache/tls"
    assert mounts["session-key"] == "/etc/attache/session"
    assert mounts["config"] == "/etc/attache/config"
    volumes = {v["name"]: v for v in dep["spec"]["template"]["spec"]["volumes"]}
    assert volumes["tls"]["secret"]["secretName"] == "embassy-tls"


@needs_helm
def test_http_tls_switches_flag_and_probe_scheme(full: list[dict]) -> None:
    flags = deployment_flags(full, "embassy")
    assert flags["http-tls"] == [""]
    assert "attache.example.com" in flags["dns-name"]
    assert "attache.example.com" in deployment_flags(full, "embassy-ca")["dns-name"]
    c = container(find(full, "Deployment", "embassy"))
    assert c["livenessProbe"]["httpGet"]["scheme"] == "HTTPS"
    assert c["readinessProbe"]["httpGet"]["scheme"] == "HTTPS"


@needs_helm
def test_every_flag_is_an_embassy_serve_flag(default: list[dict], full: list[dict]) -> None:
    used = set()
    for docs in (default, full):
        for name in ("embassy-ca", "embassy"):
            used |= set(deployment_flags(docs, name))
    assert used <= SERVE_FLAGS, used - SERVE_FLAGS
    binary = os.environ.get("EMBASSY_BIN")
    if binary and Path(binary).exists():
        help_text = subprocess.run([binary, "serve", "--help"], capture_output=True, text=True, check=True).stdout
        accepted = set(re.findall(r"--([a-z][a-z-]+)", help_text))
        assert used <= accepted, used - accepted


@needs_helm
def test_pods_are_locked_down(full: list[dict]) -> None:
    for name in ("embassy-ca", "embassy"):
        dep = find(full, "Deployment", name)
        pod = dep["spec"]["template"]["spec"]
        assert pod["securityContext"]["runAsNonRoot"] is True
        assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
        assert pod["imagePullSecrets"] == [{"name": "registry-example"}]
        sc = container(dep)["securityContext"]
        assert sc["readOnlyRootFilesystem"] is True
        assert sc["allowPrivilegeEscalation"] is False
        assert sc["capabilities"] == {"drop": ["ALL"]}


@needs_helm
def test_images_default_to_app_version_and_digest_wins(default: list[dict], full: list[dict]) -> None:
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    for name in ("embassy-ca", "embassy"):
        assert container(find(default, "Deployment", name))["image"] == (
            f"ghcr.io/f8fvwgzc/agent-sidecar/embassy:{chart['appVersion']}"
        )
        assert container(find(full, "Deployment", name))["image"] == (
            "registry.example/attache/embassy@sha256:" + "0" * 63 + "1"
        )
    assert deployment_flags(full, "embassy-ca")["injector-image"] == ["registry.example/attache/attached:0.2.0-rc.1"]


def inject_template(docs: list[dict]) -> dict:
    return json.loads(env(container(find(docs, "Deployment", "embassy-ca")))["ATTACHE_INJECT_TEMPLATE"])


@needs_helm
def test_injection_defaults_reach_embassy_ca_as_one_container_template(default: list[dict], full: list[dict]) -> None:
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert inject_template(default) == {
        "imagePullPolicy": "IfNotPresent",
        "resources": values["injection"]["resources"],
        "securityContext": values["injection"]["securityContext"],
    }
    # OTLP settings become the sidecar's own variables (design §6.1, §9)
    assert inject_template(full) == {
        "imagePullPolicy": "Always",
        "resources": values["injection"]["resources"],
        "securityContext": values["injection"]["securityContext"],
        "env": [
            {"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://otel-collector.observability:4318"},
            {"name": "ATTACHE_OTLP_ENDPOINT_ALLOW", "value": "http://otel-collector.*:4318,https://otlp.example"},
        ],
    }
    custom = render("--set", "injection.resources.limits.memory=1Gi", "--set", "otlp.endpoint=http://c:4318")
    t = inject_template(custom)
    assert t["resources"]["limits"] == {"memory": "1Gi"}
    assert t["env"] == [{"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://c:4318"}]


@needs_helm
def test_embassy_ca_gets_no_other_undesigned_variables(default: list[dict], full: list[dict]) -> None:
    # Everything else reaches embassy through the design's flags; the one extra input is documented.
    for docs in (default, full):
        for name in ("embassy-ca", "embassy"):
            names = set(env(container(find(docs, "Deployment", name))))
            extra = {"ATTACHE_INJECT_TEMPLATE"} if name == "embassy-ca" else set()
            assert names == {"RUST_LOG", "POD_NAME", "POD_NAMESPACE"} | extra, (name, names)
    readme = README.read_text()
    assert "`ATTACHE_INJECT_TEMPLATE`" in readme
    for field in ("imagePullPolicy", "resources", "securityContext", "OTEL_EXPORTER_OTLP_ENDPOINT"):
        assert field in readme


# ---- Services and NetworkPolicy -----------------------------------------------------------


@needs_helm
def test_services_expose_the_designed_ports(default: list[dict]) -> None:
    def ports(name: str) -> dict:
        svc = find(default, "Service", name)
        return {p["name"]: (p["port"], p["targetPort"]) for p in svc["spec"]["ports"]}

    assert ports("embassy-ca") == {"grpc": (15012, "grpc"), "webhook": (443, "webhook")}
    assert ports("embassy") == {"grpc": (15012, "grpc"), "http": (8080, "http")}
    for name in ("embassy-ca", "embassy"):
        svc = find(default, "Service", name)
        dep = find(default, "Deployment", name)
        assert svc["spec"]["selector"] == dep["spec"]["selector"]["matchLabels"]


@needs_helm
def test_network_policy_is_optional_and_guards_the_api(default: list[dict], full: list[dict]) -> None:
    assert not [d for d in default if d["kind"] == "NetworkPolicy"]
    policy = find(full, "NetworkPolicy", "embassy")
    assert policy["spec"]["policyTypes"] == ["Ingress"]
    rules = policy["spec"]["ingress"]
    open_rule = next(r for r in rules if r["ports"][0]["port"] == 15012)
    assert "from" not in open_rule
    api_rule = next(r for r in rules if r["ports"][0]["port"] == 8080)
    assert api_rule["from"] == [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}}
    ]
    closed = render("--set", "networkPolicy.enabled=true")
    ports = [r["ports"][0]["port"] for r in find(closed, "NetworkPolicy", "embassy")["spec"]["ingress"]]
    assert ports == [15012], "no httpFrom: nothing may reach 8080"


# ---- ControlPlaneConfig and session key ---------------------------------------------------


def config(docs: list[dict]) -> dict:
    return yaml.safe_load(find(docs, "Secret", "embassy-config")["stringData"]["config.yaml"])


@needs_helm
def test_config_secret_holds_the_control_plane_config(default: list[dict], full: list[dict]) -> None:
    assert config(default) == {
        "apiVersion": "attache.io/v1alpha1",
        "kind": "ControlPlaneConfig",
        "auth": {
            "tokens": [],
            "anonymous": "none",
            "session_key_file": "/etc/attache/session/key",
        },
        "issuance": {"kubernetes": True, "workload_cert_ttl": "24h", "join_tokens": []},
        "events": {"retain_bytes": 67108864},
    }
    cfg = config(full)
    assert cfg["auth"]["tokens"] == [
        {
            "name": "alice",
            "role": "admin",
            "sha256": "1" * 64,
            "namespaces": ["*"],
            "payloads": True,
        },
        {
            "name": "ci",
            "role": "viewer",
            "sha256": "2" * 64,
            "namespaces": ["shop", "attache-demo"],
            "payloads": False,
        },
    ]
    assert cfg["issuance"]["workload_cert_ttl"] == "12h"
    assert cfg["issuance"]["join_tokens"] == [
        {
            "name": "vm-orders",
            "sha256": "3" * 64,
            "namespace": "shop",
            "services": ["orders"],
            "expires_at": "2027-01-01T00:00:00Z",
        }
    ]
    assert cfg["policy"] == {
        "require_authz_default_deny": True,
        "http_origin_allowlist": ["https://api.partner.example"],
        "forbid_learning_auto": True,
    }
    assert cfg["events"] == {"retain_bytes": 134217728}


@needs_helm
@pytest.mark.parametrize(
    "bad",
    [
        ["--set", "auth.tokens[0].name=a", "--set", "auth.tokens[0].role=admin"],
        [
            "--set-json",
            'auth.tokens=[{"name":"a","role":"admin","sha256":"' + "A" * 64 + '"}]',
        ],
        [
            "--set-json",
            'auth.tokens=[{"name":"a","role":"admin","sha256":"' + "a" * 64 + '","token":"att_x"}]',
        ],
        ["--set-json", 'auth.tokens=[{"name":"a","role":"root","sha256":"' + "a" * 64 + '"}]'],
        ["--set", "issuance.workloadCertTTL=one day"],
        ["--set", "injection.failurePolicy=Maybe"],
        ["--set", "images.embassy.digest=latest"],
        ["--set", "unknownKey=1"],
    ],
)
def test_values_schema_refuses_bad_values(bad: list[str]) -> None:
    render_fails(*bad)


@needs_helm
def test_session_key_is_random_or_existing(default: list[dict], full: list[dict]) -> None:
    key = base64.b64decode(find(default, "Secret", "attache-session-key")["data"]["key"])
    assert len(key) >= 32
    again = base64.b64decode(find(render(), "Secret", "attache-session-key")["data"]["key"])
    assert again != key, "a fresh install gets a fresh key"
    assert ("Secret", "attache-session-key") not in kinds(full)
    volumes = find(full, "Deployment", "embassy")["spec"]["template"]["spec"]["volumes"]
    session = next(v for v in volumes if v["name"] == "session-key")
    assert session["secret"]["secretName"] == "my-session-key"


# ---- the demo apps (make demo-helm) -------------------------------------------------------


def test_demo_apps_ask_for_injection_and_match_their_charters() -> None:
    docs = [d for d in yaml.safe_load_all(DEMO_APPS.read_text()) if d]
    deployments = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Deployment"}
    accounts = {d["metadata"]["name"] for d in docs if d["kind"] == "ServiceAccount"}
    assert set(deployments) == {"orders", "inventory"}
    for name, dep in deployments.items():
        charter = yaml.safe_load((ROOT / f"examples/charters/{name}.charter.yaml").read_text())
        meta = dep["spec"]["template"]["metadata"]
        pod = dep["spec"]["template"]["spec"]
        assert dep["metadata"]["namespace"] == charter["service"]["namespace"]
        assert meta["labels"]["attache.io/inject"] == "true"
        assert meta["labels"]["attache.io/service"] == name
        assert meta["annotations"]["attache.io/service"] == name
        assert meta["annotations"]["attache.io/app-port"] == str(charter["service"]["app_port"])
        # the injected sidecar gets ANTHROPIC_API_KEY from the Secret demo.sh always creates
        assert meta["annotations"]["attache.io/anthropic-secret"] == "attache-anthropic"
        assert pod["serviceAccountName"] == name and name in accounts
        assert [c["name"] for c in pod["containers"]] == ["app"], "the webhook adds attached"
        assert "initContainers" not in pod
    services = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Service"}
    for name, svc in services.items():
        mesh = [p for p in svc["spec"]["ports"] if p["name"] == "mesh"]
        assert mesh == [{"name": "mesh", "port": 50002, "targetPort": 50002}]


def test_demo_script_parses_and_creates_the_anthropic_secret() -> None:
    assert os.access(DEMO_SCRIPT, os.X_OK)
    subprocess.run(["bash", "-n", str(DEMO_SCRIPT)], check=True)
    text = DEMO_SCRIPT.read_text()
    assert "create secret generic attache-anthropic" in text
    assert not re.search(r'--from-literal=ANTHROPIC_API_KEY="?\$', text), "the key must not be on the command line"
    # created before the apps, so their pods never wait for it
    assert text.index("attache-anthropic") < text.index("deploy/helm/demo/apps.yaml")
