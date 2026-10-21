"""Check the golden API data in ui/fixtures against docs/api/openapi.yaml and the design.

Run from anywhere:

    uv run --no-project --with pyyaml --with jsonschema python3 -I docs/api/check_fixtures.py

What it checks (every check names the file and the place that failed):

- the OpenAPI document: every `$ref` resolves; every operation's role agrees with the role table
  of design §10; every mutating operation takes the CSRF header and documents 400 and 403;
  adoption is `editor` without role-on-diff; `PUT .../memory` takes `Note` or `NoteInput`; the
  record → edge mapping (design §10.1) and the audit drop rule (design §7) are quoted exactly;
- every fixture validates against the schema of the operation that names it (`x-fixture`), and
  every SSE event against its `x-sse-events` schema; every fixture file is named by an operation;
- id formats (node and edge ids, UUIDs, trace and span ids, timestamps, versions, hashes);
- the graph follows the design rules: derived from the stored charters, every edge endpoint is a
  node, placeholders for unknown peers, statuses and learning badges agree with the other files;
- the record → edge mapping (design §10.1) for every SSE audit event, and the edge stats
  against the records of events-recent.json;
- the drop rule (design §7) for events-recent.json and the SSE audit events;
- the order of events-recent.json (newest first, equal timestamps in reverse write order) and of
  the audit events of events.sse (write order);
- the charters: plain YAML equal to their JSON, valid against schemas/charter.schema.json and,
  when the attache CLI is built (target/debug/attache, or --attache PATH), `attache charter
  validate`;
- the fixtures cover every v0.2 UI path of design §11.

Exit status 0 when everything holds, 1 with one line per problem otherwise. `--self-test` then
also applies known-bad edits to an in-memory copy (a tie out of order, an inbound record made
outbound, a wrong `edge_id`, adoption checked on the diff, ...) and fails unless each is reported.
Lint with `ruff check --line-length 120` (the runtime's settings).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry
from referencing.jsonschema import DRAFT202012

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "ui" / "fixtures"
OPENAPI = REPO / "docs" / "api" / "openapi.yaml"
DESIGN = REPO / "docs" / "design" / "agent-platform.md"
CHARTER_SCHEMA = REPO / "schemas" / "charter.schema.json"
OPENAPI_URI = "urn:attache:openapi"

# What the per-resource fixtures answer (the README table says the same).
AGENT_VIEWS = {
    "agent-view.json": ("attache-demo", "orders", "ops-assistant"),
    "agent-view-support.json": ("attache-demo", "support", "support-agent"),
}
MEMORY_OF = ("attache-demo", "support")
HISTORY_OF = ("attache-demo", "orders")
VALIDATE_OF = ("attache-demo", "support")  # charter-validate.json: a candidate for this service

DNS_LABEL = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+$")
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
NODE_ID = {
    "service": re.compile(rf"^svc:({DNS_LABEL})/({DNS_LABEL})$"),
    "app": re.compile(rf"^app:({DNS_LABEL})/({DNS_LABEL})$"),
    "agent": re.compile(rf"^agent:({DNS_LABEL})/({DNS_LABEL})/({DNS_LABEL})$"),
    "model_provider": re.compile(r"^model:(anthropic|mock)$"),
    "external": re.compile(r"^external:(https?)://([^/?#:@\s]+)(?::(\d+))?$"),
}
INLINE_SKILL_BYTES = 2048  # design §4: a skill is inline when its instructions are shorter
STATS_WINDOW = timedelta(minutes=15)  # design §10.1
MAX_RECORD_BYTES = 64 * 1024  # design §7
# The order a sidecar writes records that end at the same millisecond (CONTRACT.md §6): a
# tool_call before the call record it made, the other records of a span before its
# agent_invocation.
WRITE_RANK = {"tool_call": 0, "agent_call": 1, "service_call": 1, "http_call": 1, "agent_invocation": 3}
MUTATING = ("post", "put", "delete", "patch")


class Problems:
    def __init__(self) -> None:
        self.items: list[str] = []
        self.checks = 0

    def check(self, ok: bool, where: str, what: str) -> bool:
        self.checks += 1
        if not ok:
            self.items.append(f"{where}: {what}")
        return ok


P = Problems()


class Source:
    """What the checks read: the fixture files by name, the OpenAPI document, the design text."""

    def __init__(self, files: dict[str, str], openapi: dict, design: str) -> None:
        self.files = files
        self.doc = openapi
        self.design = design

    @classmethod
    def from_disk(cls, fixtures: Path) -> Source:
        files = {f.name: f.read_text() for f in sorted(fixtures.iterdir()) if f.is_file()}
        return cls(files, yaml.safe_load(OPENAPI.read_text()), DESIGN.read_text())


SRC: Source


def load_json(name: str):
    return json.loads(SRC.files[name])


def ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def norm(text: str) -> str:
    return " ".join(text.split())


def rank(rec: dict) -> int:
    return WRITE_RANK.get(rec["kind"], 2)


# ---- the OpenAPI document ----------------------------------------------------------------------


def walk_refs(v, path="#"):
    if isinstance(v, dict):
        for k, x in v.items():
            if k == "$ref":
                yield path, x
            yield from walk_refs(x, f"{path}/{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from walk_refs(x, f"{path}/{i}")


def resolve_pointer(doc, ref: str):
    if not ref.startswith("#/"):
        return None
    node = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def operations(doc):
    for path, item in doc["paths"].items():
        for method, op in item.items():
            if method in ("get", "post", "put", "delete", "patch"):
                yield path, method, op


def design_role_table(design: str) -> list[tuple[str, str, str]]:
    """(METHOD, path, role cell) for every operation in the table of design §10."""
    start = design.index("| Method and path | Role |")
    rows = []
    for line in design[start:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        # split on "|" outside `code` (cells quote shapes such as `{...}|null`)
        cells, cell, code = [], "", False
        for ch in line.strip().strip("|"):
            if ch == "`":
                code = not code
            if ch == "|" and not code:
                cells.append(cell.strip())
                cell = ""
            else:
                cell += ch
        cells.append(cell.strip())
        rows.append((cells[0], cells[1]))
    out = []
    for cell, role in rows:
        roles = [r.strip() for r in role.split(" / ")] if role.startswith("viewer / ") else None
        ops = []
        last_method = last_path = None
        for seg in re.findall(r"`([^`]*)`", cell):
            m = re.match(r"^(GET|POST|PUT|DELETE|PATCH)(?: (\S+))?$", seg)
            if m:
                method, path = m.group(1), m.group(2)
                if path is not None:
                    path = path.split("?", 1)[0]
                if path is None:
                    path = last_path
                elif path.startswith(".../history/"):
                    path = "/services/{ns}/{svc}/charter" + path[3:]
                elif path.startswith("..."):
                    path = "/services/{ns}/{svc}" + path[3:]
                ops.append((method, path))
                last_method, last_path = method, path
            elif re.match(r"^[a-z]+$", seg) and last_path and " / `" + seg in cell:
                # "`POST /proposals/{id}/approve` / `reject`"
                path = last_path.rsplit("/", 1)[0] + "/" + seg
                ops.append((last_method, path))
        for i, (method, path) in enumerate(ops):
            out.append((method, path, roles[i] if roles else role))
    return out


def check_openapi(doc, design: str) -> None:
    where = "docs/api/openapi.yaml"
    P.check(doc.get("openapi") == "3.1.0", where, "openapi is not 3.1.0")
    refs = list(walk_refs(doc))
    P.check(len(refs) > 100, where, f"only {len(refs)} $refs")
    for at, ref in refs:
        P.check(resolve_pointer(doc, ref) is not None, where, f"{at}: $ref {ref} does not resolve")

    ops = {(m.upper(), p): op for p, m, op in operations(doc)}
    # design §10 role table ↔ x-required-role / x-role-on-diff
    table = design_role_table(design)
    P.check(len(table) >= 28, "design §10", f"role table parsed into {len(table)} operations")
    seen = set()
    for method, path, role in table:
        key = (method, path)
        seen.add(key)
        op = ops.get(key)
        if not P.check(op is not None, where, f"{method} {path} (design §10) is not documented"):
            continue
        got = op.get("x-required-role")
        diff = op.get("x-role-on-diff") is True
        want = {
            "any": {"none", "viewer"},
            "none": {"none"},
            "viewer": {"viewer"},
            "editor": {"editor"},
            "admin": {"admin"},
            "role on diff": {"editor"},
            "editor (+role on diff)": {"editor"},
            "editor (same service) / admin (cross service)": {"editor"},
        }.get(role)
        if not P.check(want is not None, "design §10", f"{method} {path}: unknown role {role!r}"):
            continue
        P.check(got in want, where, f"{method} {path}: x-required-role {got!r}, design §10 says {role!r}")
        if "diff" in role or "(same service)" in role:
            P.check(diff, where, f"{method} {path}: design §10 says {role!r}, x-role-on-diff is not true")
    for key in ops:
        P.check(key in seen, where, f"{key[0]} {key[1]} is not in the design §10 table")

    # charter-changing operations are checked on the diff, adoption is not
    for key in [
        ("PUT", "/services/{ns}/{svc}/charter"),
        ("POST", "/services/{ns}/{svc}/agents"),
        ("PUT", "/services/{ns}/{svc}/agents/{agent}"),
        ("DELETE", "/services/{ns}/{svc}/agents/{agent}"),
        ("PUT", "/services/{ns}/{svc}/skills/{skill}"),
        ("DELETE", "/services/{ns}/{svc}/skills/{skill}"),
        ("POST", "/links"),
    ]:
        op = ops.get(key, {})
        P.check(
            op.get("x-required-role") == "editor" and op.get("x-role-on-diff") is True,
            where,
            f"{key[0]} {key[1]}: must be editor with x-role-on-diff: true",
        )
    adopt = ops.get(("POST", "/services/{ns}/{svc}/adopt"), {})
    P.check(adopt.get("x-required-role") == "editor", where, "adopt must need editor")
    P.check(adopt.get("x-role-on-diff") is not True, where, "adopt has no stored charter to diff against")
    text = norm(adopt.get("description", ""))
    for want in ("charter validator", "`policy`", "no role-on-diff check"):
        P.check(want in text, where, f"adopt description does not say {want!r}")

    # every mutating request: CSRF header, 400 (content type), 403 (CSRF)
    for (method, path), op in ops.items():
        if method.lower() not in MUTATING:
            continue
        params = [p.get("$ref", p.get("name")) for p in op.get("parameters", [])]
        P.check("#/components/parameters/Csrf" in params, where, f"{method} {path}: no X-Attache-CSRF parameter")
        for status in ("400", "403"):
            P.check(status in op.get("responses", {}), where, f"{method} {path}: does not document {status}")

    schemas = doc["components"]["schemas"]
    items = schemas["MemoryPut"]["properties"]["agents"]["additionalProperties"]["items"]
    P.check(
        sorted(x.get("$ref", "") for x in items.get("oneOf", []))
        == ["#/components/schemas/Note", "#/components/schemas/NoteInput"],
        where,
        "MemoryPut entries must be oneOf Note, NoteInput",
    )
    note_input = schemas.get("NoteInput", {})
    P.check(
        note_input.get("required") == ["text"] and set(note_input.get("properties", {})) == {"id", "text"},
        where,
        "NoteInput is {id?, text}",
    )

    # the lenient audit view (design §5)
    rec = schemas["AuditRecord"]
    P.check(rec.get("additionalProperties") is True, where, "AuditRecord must keep unknown fields")
    for f in ("kind", "direction", "decision"):
        P.check("enum" not in rec["properties"][f], where, f"AuditRecord.{f} must be any string")
    P.check(schemas["Tokens"].get("additionalProperties") is not False, where, "Tokens must accept unknown fields")

    # design text quoted exactly
    start = design.index("**Record → edge mapping**")
    end = design.index("triggers `event: graph`.", start) + len("triggers `event: graph`.")
    mapping = design[start:end]
    P.check(
        norm(mapping) in norm(schemas["Edge"]["description"]),
        where,
        "Edge.description does not quote the record → edge mapping of design §10.1 exactly",
    )
    drop = next(line for line in design.splitlines() if line.startswith("- Every received audit record:"))
    P.check(
        norm(drop[2:]) in norm(rec["description"]),
        where,
        "AuditRecord.description does not quote the drop rule of design §7 exactly",
    )

    events = doc["paths"]["/events"]["get"]["x-sse-events"]
    P.check(
        set(events) == {"audit", "graph", "registry", "config", "ack", "proposal", "cp_audit", "lagged", "reset"},
        where,
        f"x-sse-events lists {sorted(events)}",
    )


# ---- schema validation of every fixture --------------------------------------------------------


def validators(doc):
    registry = Registry().with_resource(OPENAPI_URI, DRAFT202012.create_resource(doc))
    cache = {}

    def for_schema(schema: dict):
        key = json.dumps(schema, sort_keys=True)
        if key not in cache:
            # resolve local refs against the whole document
            s = json.loads(json.dumps(schema).replace('"#/', f'"{OPENAPI_URI}#/'))
            cache[key] = Draft202012Validator(s, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER)
        return cache[key]

    return for_schema


def validate(v, instance, where: str) -> None:
    try:
        errors = sorted(v.iter_errors(instance), key=lambda e: list(e.absolute_path))
    except Exception as e:  # an unresolvable $ref: reported by check_openapi too
        P.check(False, where, f"schema: cannot validate: {type(e).__name__}: {str(e)[:120]}")
        return
    for e in errors[:5]:
        path = "/".join(str(p) for p in e.absolute_path)
        P.check(False, where, f"schema: at /{path}: {e.message[:200]}")
    if not errors:
        P.check(True, where, "")


def sse_frames():
    frames = []
    text = SRC.files["events.sse"]
    P.check(text.endswith("\n"), "events.sse", "does not end with a newline")
    for block in text.split("\n\n"):
        fid = event = None
        data = []
        for line in block.splitlines():
            if not line or line.startswith(":"):
                continue
            field, _, value = line.partition(": ")
            if field == "id":
                fid = int(value) if VERSION.match(value) else None
                P.check(fid is not None, "events.sse", f"id {value!r} is not a decimal")
            elif field == "event":
                event = value
            elif field == "data":
                data.append(value)
            else:
                P.check(False, "events.sse", f"unexpected field {field!r}")
        if fid is None and event is None and not data:
            continue
        if P.check(fid is not None and event is not None and data, "events.sse", f"incomplete event: {block[:80]!r}"):
            frames.append((fid, event, json.loads("\n".join(data))))
    return frames


def check_schemas(doc) -> None:
    for_schema = validators(doc)
    named = set()
    for path, method, op in operations(doc):
        fx = op.get("x-fixture")
        if not fx:
            continue
        files = fx if isinstance(fx, list) else [fx]
        for f in files:
            name = f.removeprefix("ui/fixtures/")
            named.add(name)
            if not P.check(name in SRC.files, "openapi.yaml", f"{method.upper()} {path}: x-fixture {f} is missing"):
                continue
            if name.endswith(".sse"):
                events = op["x-sse-events"]
                for fid, event, data in sse_frames():
                    schema = events.get(event)
                    if P.check(schema is not None, "events.sse", f"id {fid}: undocumented event {event!r}"):
                        validate(for_schema(schema), data, f"events.sse id {fid} ({event})")
                continue
            schema = op["responses"]["200"]["content"]["application/json"]["schema"]
            validate(for_schema(schema), load_json(name), f"ui/fixtures/{name}")
    for name in SRC.files:
        if name != "README.md":
            P.check(name in named, f"ui/fixtures/{name}", "no operation names it in x-fixture")


# ---- the world ---------------------------------------------------------------------------------


class World:
    def __init__(self) -> None:
        self.whoami = load_json("whoami.json")
        self.viewer = load_json("whoami-viewer.json")
        self.validate_result = load_json("charter-validate.json")
        self.links = load_json("links-result.json")
        self.graph = load_json("graph.json")
        self.services = load_json("services.json")
        self.memory = load_json("memory.json")
        self.proposals = load_json("proposals.json")
        self.history = load_json("history.json")
        self.recent = load_json("events-recent.json")
        self.frames = sse_frames()
        self.views = {name: load_json(name) for name in AGENT_VIEWS}
        self.charters = {}  # (ns, svc) -> charter doc
        for name in sorted(SRC.files):
            if not name.startswith("charter-") or name == "charter-validate.json":
                continue
            doc = load_json(name)
            c = doc["charter"]
            self.charters[(c["service"]["namespace"], c["service"]["name"])] = (name, doc)
        self.nodes = {n["id"]: n for n in self.graph["nodes"]}
        self.edges = {e["id"]: e for e in self.graph["edges"]}
        self.generated = ts(self.graph["generated_at"])

    def charter(self, ns, svc):
        got = self.charters.get((ns, svc))
        return got[1]["charter"] if got else None

    def agent_spec(self, ns, svc, agent):
        c = self.charter(ns, svc)
        return next((a for a in c["agents"] if a["name"] == agent), None) if c else None


def tool_target(ns: str, svc: str, tool: dict) -> str:
    """Design §10.1: the node a declared tool reaches."""
    if tool["type"] == "agent":
        return f"agent:{ns}/{tool.get('service') or svc}/{tool['agent']}"
    if tool["type"] == "service":
        return f"app:{ns}/{tool['service']}"
    u = urlsplit(tool["url"])
    return f"external:{u.scheme}://{u.netloc}"


def allowed_tools(charter: dict, agent: dict) -> list[str]:
    declared = [t["name"] for t in agent.get("tools", [])]
    narrowed = charter.get("guardrails", {}).get("allowed_tools", {}).get(agent["name"])
    return [t for t in declared if narrowed is None or t in narrowed]


def admitted_locally(charter: dict, agent: str) -> bool:
    for rule in charter.get("authz", {}).get("callers", []):
        if rule["identity"] == "local" and ("*" in rule.get("agents", []) or agent in rule.get("agents", [])):
            return True
    return False


def edge_id(kind, source, target, tool=None):
    return f"edge:{kind}:{source}->{target}" + (f"#{tool}" if tool else "")


def check_ids(w: World) -> None:
    for n in w.graph["nodes"]:
        where = f"graph.json node {n['id']}"
        m = NODE_ID.get(n["type"], re.compile("^$")).match(n["id"]) if n["type"] in NODE_ID else None
        if not P.check(m is not None, where, f"id does not fit type {n['type']}"):
            continue
        if n.get("placeholder"):
            P.check(n["status"] == "disconnected", where, "placeholders are disconnected")
        if n["type"] == "service" and not n.get("placeholder"):
            P.check(m.groups() == (n["namespace"], n["service"]), where, "id is not svc:<namespace>/<service>")
            P.check(n["label"] == n["service"], where, "label is the service name")
        if n["type"] in ("app", "agent"):
            ns, svc = m.group(1), m.group(2)
            P.check(n.get("parent") == f"svc:{ns}/{svc}", where, "parent is not its service node")
            P.check(n.get("parent") in w.nodes, where, f"parent {n.get('parent')} is not a node")
        if n["type"] == "agent":
            P.check(n["label"] == m.group(3), where, "label is the agent name")
        if n["type"] == "external":
            scheme, host, port = m.groups()
            want = host + (f":{port}" if port else "")
            P.check(n["label"] == want, where, f"label {n['label']!r}, want {want!r}")
            P.check(not port or (scheme, port) not in (("https", "443"), ("http", "80")), where, "default port in id")
    for e in w.graph["edges"]:
        where = f"graph.json edge {e['id']}"
        tool = e["source_port"] if e["kind"] == "tool" else None
        P.check(
            e["id"] == edge_id(e["kind"], e["source"], e["target"], tool),
            where,
            "id is not edge:<kind>:<source>-><target>[#<tool>]",
        )
        for end in ("source", "target"):
            P.check(e[end] in w.nodes, where, f"{end} {e[end]} is not a node")
        if e["source"] in w.nodes and e["target"] in w.nodes:
            src, dst = w.nodes[e["source"]], w.nodes[e["target"]]
            P.check(e["target_port"] in dst["ports"]["in"], where, f"target port {e['target_port']} not on {dst['id']}")
            if e["declared"]:
                P.check(
                    e["source_port"] in src["ports"]["out"], where, f"source port {e['source_port']} not on {src['id']}"
                )
        s = e["stats"]
        P.check(s["denied"] <= s["calls"] and s["errors"] <= s["calls"], where, "denied/errors above calls")
        P.check(s["calls"] > 0 or s["avg_ms"] == 0, where, "avg_ms without calls")
        P.check(s["calls"] == 0 or s["last_ts"] is not None, where, "calls without last_ts")
    P.check(len(w.nodes) == len(w.graph["nodes"]), "graph.json", "duplicate node ids")
    P.check(len(w.edges) == len(w.graph["edges"]), "graph.json", "duplicate edge ids")
    P.check(VERSION.match(w.graph["version"]) is not None, "graph.json", "version is not decimal")

    def stamp(value, where):
        P.check(
            isinstance(value, str) and TS.match(value) is not None,
            where,
            f"timestamp {value!r} is not RFC 3339 UTC with ms",
        )

    stamp(w.graph["generated_at"], "graph.json generated_at")
    for s in w.services:
        where = f"services.json {s['service']}"
        P.check(s["epoch"] is None or UUID4.match(s["epoch"]) is not None, where, "epoch is not a UUIDv4")
        if s["pending_adoption"]:
            P.check(SHA256.match(s["pending_adoption"]["sha256"]) is not None, where, "pending sha256")
            stamp(s["pending_adoption"]["ts"], where)
        for i in s["instances"]:
            P.check(UUID4.match(i["instance_id"]) is not None, where, f"instance_id {i['instance_id']}")
            stamp(i["connected_at"], where)
            if i["last_heartbeat"]:
                stamp(i["last_heartbeat"], where)
    for name, doc in w.charters.values():
        P.check(UUID4.match(doc["epoch"]) is not None, name, "epoch is not a UUIDv4")
        P.check(VERSION.match(doc["version"]) is not None, name, "version is not decimal")
    for h in w.history:
        stamp(h["ts"], "history.json")
        P.check(SHA256.match(h["sha256"]) is not None, "history.json", "sha256")
    for p in w.proposals:
        P.check(UUID4.match(p["id"]) is not None, "proposals.json", f"id {p['id']} is not a UUIDv4")
        P.check(UUID4.match(p["request_id"]) is not None, "proposals.json", f"{p['id']}: request_id")
        P.check(TRACE_ID.match(p["trace_id"]) is not None, "proposals.json", f"{p['id']}: trace_id")
        stamp(p["ts"], f"proposals.json {p['id']}")
    for agent, notes in w.memory["agents"].items():
        for n in notes:
            P.check(UUID4.match(n["id"]) is not None, "memory.json", f"{agent}: note id {n['id']}")
            stamp(n["ts"], f"memory.json {n['id']}")
    records = [("events-recent.json", r) for r in w.recent] + [
        (f"events.sse id {fid}", d["record"]) for fid, ev, d in w.frames if ev == "audit"
    ]
    for where, r in records:
        where = f"{where} ({r['kind']} {r['ts']})"
        stamp(r["ts"], where)
        P.check(UUID4.match(r["request_id"]) is not None, where, "request_id is not a UUIDv4")
        P.check(TRACE_ID.match(r["trace_id"]) is not None, where, "trace_id is not 32 hex")
        P.check(SPAN_ID.match(r["span_id"]) is not None, where, "span_id is not 16 hex")
        P.check(r["parent_span_id"] is None or SPAN_ID.match(r["parent_span_id"]) is not None, where, "parent_span_id")
    for fid, ev, d in w.frames:
        if ev in ("registry", "ack"):
            P.check(UUID4.match(d["instance_id"]) is not None, f"events.sse id {fid}", "instance_id")
        if ev == "cp_audit":
            stamp(d["ts"], f"events.sse id {fid}")


# ---- graph against charters, services, memory, proposals ---------------------------------------


def check_graph(w: World) -> None:
    by_service = {(s["namespace"], s["service"]): s for s in w.services}
    P.check(list(by_service) == sorted(by_service), "services.json", "not sorted by namespace, then service")
    expected_nodes = set()
    expected_edges = set()
    targets = set()
    for (ns, svc), s in by_service.items():
        where = f"services.json {svc}"
        node = w.nodes.get(f"svc:{ns}/{svc}")
        if not P.check(node is not None and not node.get("placeholder"), where, "no service node"):
            continue
        expected_nodes.add(node["id"])
        P.check(node["status"] == s["status"], where, f"graph status {node['status']}, services {s['status']}")
        P.check(node["instances"] == len(s["instances"]), where, "instance count differs from the graph")
        P.check(node["charter_version"] == s["charter_version"], where, "charter_version differs from the graph")
        connected = bool(s["instances"])
        stored = w.charters.get((ns, svc))
        # status rules (OpenAPI ServiceStatus)
        if stored is None:
            P.check(
                s["status"] == "no_charter" and connected, where, "no stored charter: status no_charter with instances"
            )
            P.check(
                s["epoch"] is None and s["charter_version"] is None and s["memory_version"] is None,
                where,
                "no stored charter: epoch, versions null",
            )
        elif not connected:
            P.check(s["status"] == "disconnected", where, "a stored charter and no instance is disconnected")
        else:
            lagging = [
                i
                for i in s["instances"]
                if i["ack_error"] or i["acked_version"] != s["charter_version"] or not i["runtime_ready"]
            ]
            P.check(
                s["status"] == ("degraded" if lagging else "connected"),
                where,
                f"status {s['status']} with lagging {len(lagging)}",
            )
        if s["pending_adoption"]:
            P.check(stored is None, where, "a pending adoption only exists without a stored charter")
        app_id = f"app:{ns}/{svc}"
        app = w.nodes.get(app_id)
        if P.check(app is not None, where, f"no node {app_id}"):
            expected_nodes.add(app_id)
            P.check(app["ports"]["out"] == ["invoke"], app_id, "app out ports")
        if stored is None:
            continue
        name, doc = stored
        P.check(
            doc["epoch"] == s["epoch"] and doc["version"] == s["charter_version"],
            name,
            "epoch/version differ from services.json",
        )
        c = doc["charter"]
        if app:
            P.check(app["port"] == c["service"]["app_port"], app_id, "port is not service.app_port")
        for a in c["agents"]:
            aid = f"agent:{ns}/{svc}/{a['name']}"
            n = w.nodes.get(aid)
            if not P.check(n is not None and not n.get("placeholder"), "graph.json", f"no node {aid}"):
                continue
            expected_nodes.add(aid)
            P.check(n["agent_type"] == a.get("type", "agent"), aid, "agent_type")
            P.check(n["model"] == a["model"], aid, "model")
            P.check(n["skills"] == a.get("skills", []), aid, "skills")
            tools = a.get("tools", [])
            allowed = allowed_tools(c, a)
            P.check(n["ports"] == {"in": ["invoke"], "out": [t["name"] for t in tools] + ["model"]}, aid, "ports")
            want_tools = [
                {
                    "name": t["name"],
                    "type": t["type"],
                    "target": tool_target(ns, svc, t),
                    "allowed": t["name"] in allowed,
                }
                for t in tools
            ]
            P.check(n["tools"] == want_tools, aid, f"tools {n['tools']} != {want_tools}")
            for t in want_tools:
                targets.add(t["target"])
                expected_edges.add(edge_id("tool", aid, t["target"], t["name"]))
            provider = "model:mock" if a["model"] == "mock" else "model:anthropic"
            targets.add(provider)
            expected_edges.add(edge_id("model", aid, provider))
            if admitted_locally(c, a["name"]):
                expected_edges.add(edge_id("invoke", app_id, aid))
            # learning badge
            lrn = a.get("learning") or {}
            notes = w.memory["agents"].get(a["name"], []) if (ns, svc) == MEMORY_OF else []
            pending = [
                p
                for p in w.proposals
                if (p["namespace"], p["service"], p["agent"]) == (ns, svc, a["name"]) and p["status"] == "pending"
            ]
            want = {
                "enabled": lrn.get("enabled", False),
                "mode": lrn.get("mode", "review"),
                "notes": len(notes),
                "pending": len(pending),
            }
            P.check(n["learning"] == want, aid, f"learning {n['learning']} != {want}")
            # status from stats (OpenAPI AgentStatus)
            st = n["stats"]
            want_status = (
                "errors" if st["errors"] else "denied" if st["denied"] else "ok" if st["invocations"] else "idle"
            )
            P.check(n["status"] == want_status, aid, f"status {n['status']}, stats say {want_status}")
        if (ns, svc) != MEMORY_OF:
            P.check(s["memory_version"] == "0", where, "memory_version of a service without a memory fixture")
    # app input ports: "service" when a declared service tool targets the app
    for nid, n in w.nodes.items():
        if n["type"] == "app" and not n.get("placeholder"):
            want = ["service"] if nid in targets else []
            P.check(n["ports"]["in"] == want, nid, f"in ports {n['ports']['in']}, want {want}")
    # every tool target is a node: known, a provider/external, or a placeholder for an unknown peer
    for t in targets:
        n = w.nodes.get(t)
        if not P.check(n is not None, "graph.json", f"tool target {t} is not a node"):
            continue
        expected_nodes.add(t)
        known = t.startswith(("model:", "external:")) or any(
            t == f"app:{ns}/{svc}" or t.startswith(f"agent:{ns}/{svc}/") for ns, svc in by_service
        )
        if not known:
            P.check(n.get("placeholder") is True, t, "a peer the control plane does not know must be a placeholder")
            parent = n.get("parent")
            if parent:
                expected_nodes.add(parent)
                P.check(w.nodes.get(parent, {}).get("placeholder") is True, t, "its service is a placeholder too")
    # nothing else: every node and declared edge comes from the rules above
    for e in w.graph["edges"]:
        if not e["declared"]:
            for end in (e["source"], e["target"]):
                expected_nodes.add(end)
    for nid in w.nodes:
        P.check(nid in expected_nodes, "graph.json", f"node {nid} does not follow from the charters, services or edges")
    declared = {e["id"] for e in w.graph["edges"] if e["declared"]}
    P.check(
        declared == expected_edges,
        "graph.json",
        f"declared edges differ from the charters: extra {sorted(declared - expected_edges)}, "
        f"missing {sorted(expected_edges - declared)}",
    )


def check_documents(w: World) -> None:
    # agent views are the charter's agents with the policy around them
    for name, (ns, svc, agent) in AGENT_VIEWS.items():
        v = w.views[name]
        c = w.charter(ns, svc)
        a = w.agent_spec(ns, svc, agent)
        if not P.check(a is not None, name, f"no agent {agent} in {svc}'s charter"):
            continue
        P.check(v["agent"] == a, name, "agent differs from the charter")
        g = c.get("guardrails", {})
        P.check(v["allowed_tools"] == g.get("allowed_tools", {}).get(agent), name, "allowed_tools")
        P.check(v["allowed_services"] == g.get("allowed_services", {}).get(agent), name, "allowed_services")
        want = [
            {"identity": r["identity"], "caller_agents": r.get("caller_agents")}
            for r in c.get("authz", {}).get("callers", [])
            if "*" in r.get("agents", []) or agent in r.get("agents", [])
        ]
        P.check(v["callers"] == want, name, f"callers {v['callers']} != {want}")
    # history
    ns, svc = HISTORY_OF
    name, doc = w.charters[(ns, svc)]
    versions = [h["version"] for h in w.history]
    P.check(versions == sorted(versions, key=int, reverse=True), "history.json", "not newest first")
    P.check(versions[0] == doc["version"], "history.json", f"newest is not {name}'s version")
    P.check(w.history[0]["sha256"] == sha(doc["yaml"]), "history.json", f"newest sha256 is not {name}'s yaml")
    # memory: only agents with learning enabled, within their limits; provenance
    ns, svc = MEMORY_OF
    s = next(x for x in w.services if (x["namespace"], x["service"]) == (ns, svc))
    P.check(s["memory_version"] == w.memory["version"], "memory.json", "version differs from services.json")
    total = 0
    for agent, notes in w.memory["agents"].items():
        a = w.agent_spec(ns, svc, agent)
        lrn = (a or {}).get("learning") or {}
        if not P.check(lrn.get("enabled") is True, "memory.json", f"{agent} has no learning enabled (design §3)"):
            continue
        P.check(len(notes) <= lrn.get("max_notes", 20), "memory.json", f"{agent}: more than max_notes")
        for n in notes:
            where = f"memory.json {n['id']}"
            total += len(n["text"])
            P.check(len(n["text"]) <= lrn.get("max_note_chars", 500), where, "longer than max_note_chars")
            if n["source"] == "review":
                P.check(
                    n["approved_by"] is not None and n["expires_at"] is None,
                    where,
                    "review notes are approved, never expire",
                )
                P.check(
                    any(
                        p["status"] == "approved"
                        and p["note"] == n["text"]
                        and p["agent"] == agent
                        and p["request_id"] == n["request_id"]
                        for p in w.proposals
                    ),
                    where,
                    "no approved proposal for this note",
                )
            elif n["source"] == "manual":
                P.check(
                    n["approved_by"] is not None
                    and n["request_id"] is None
                    and n["trace_id"] is None
                    and n["expires_at"] is None,
                    where,
                    "manual notes: approved_by the author, no request, no expiry",
                )
            else:
                P.check(
                    n["approved_by"] is None and n["expires_at"] is not None,
                    where,
                    "auto notes expire, nobody approved them",
                )
        P.check([n["ts"] for n in notes] == sorted(n["ts"] for n in notes), "memory.json", f"{agent}: not oldest first")
    P.check(total <= 262144, "memory.json", "more than 262144 characters")
    # proposals: newest first, of agents with learning enabled
    stamps = [p["ts"] for p in w.proposals]
    P.check(stamps == sorted(stamps, reverse=True), "proposals.json", "not newest first")
    for p in w.proposals:
        a = w.agent_spec(p["namespace"], p["service"], p["agent"])
        P.check(
            a is not None and (a.get("learning") or {}).get("enabled") is True,
            "proposals.json",
            f"{p['id']}: {p['service']}/{p['agent']} has no learning enabled",
        )
        if p["auto"]:
            P.check(p["status"] == "approved", "proposals.json", f"{p['id']}: auto proposals are approved")
    # the validate result: a candidate that drops guardrail rules is weakened and needs admin
    stored = w.charter(*VALIDATE_OF)
    cand = w.validate_result["charter"]
    removed = []
    for key in ("input_deny", "output_deny"):
        names = {r["name"] for r in cand.get("guardrails", {}).get(key, [])}
        removed += [
            f"guardrails.{key}[{r['name']}]"
            for r in stored.get("guardrails", {}).get(key, [])
            if r["name"] not in names
        ]
    P.check(
        w.validate_result["weakened"] == removed,
        "charter-validate.json",
        f"weakened {w.validate_result['weakened']}, removed rules {removed}",
    )
    if removed:
        P.check(
            w.validate_result["needs_role"] == "admin",
            "charter-validate.json",
            "guardrails rules need admin (design §8.3)",
        )
    rest = {k: v for k, v in cand.items() if k != "guardrails"}
    P.check(
        rest == {k: v for k, v in stored.items() if k != "guardrails"},
        "charter-validate.json",
        "the candidate changes more than guardrails",
    )
    # the link result: applied writes are the next version, failed ones name the current one
    for a in w.links["applied"]:
        ns, svc = a["service"].split("/")
        doc = w.charters.get((ns, svc))
        P.check(
            doc is not None and int(a["version"]) == int(doc[1]["version"]) + 1, "links-result.json", f"applied {a}"
        )
    for key, err in w.links["failed"].items():
        ns, svc = key.split("/")
        doc = w.charters.get((ns, svc))
        if err["error"] == "version_conflict":
            P.check(
                doc is not None and err.get("current_version") == doc[1]["version"],
                "links-result.json",
                f"failed {key}: current_version",
            )
    # charters: YAML equal to JSON, valid against the JSON Schema
    schema = json.loads(CHARTER_SCHEMA.read_text())
    v = Draft202012Validator(schema)
    validate(v, cand, "charter-validate.json charter (schemas/charter.schema.json)")
    for (ns, svc), (name, doc) in w.charters.items():
        P.check(yaml.safe_load(doc["yaml"]) == doc["charter"], name, "charter is not its yaml as JSON")
        validate(v, doc["charter"], f"{name} (schemas/charter.schema.json)")
        P.check(
            any((s["namespace"], s["service"]) == (ns, svc) for s in w.services), name, "no service in services.json"
        )
        example = REPO / "examples" / "charters" / f"{svc}.charter.yaml"
        if example.exists():
            P.check(doc["yaml"] == example.read_text(), name, f"yaml is not {example.relative_to(REPO)}")


def run_cli_validate(w: World, attache: Path | None) -> None:
    if attache is None:
        return
    texts = [(name, doc["yaml"]) for name, doc in w.charters.values()]
    # the validate candidate is JSON, which YAML reads as it is
    texts.append(("charter-validate.json", json.dumps(w.validate_result["charter"], indent=2)))
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in texts:
            f = Path(tmp) / (name.removesuffix(".json") + ".yaml")
            f.write_text(text)
            r = subprocess.run([str(attache), "charter", "validate", str(f)], capture_output=True, text=True)
            P.check(
                r.returncode == 0 and r.stdout.startswith("valid: "),
                name,
                f"attache charter validate: {r.stdout.strip()} {r.stderr.strip()}",
            )


# ---- records -----------------------------------------------------------------------------------


def expected_edge(rec: dict, spans: dict) -> str | None:
    """Design §10.1: the edge a record animates, or None. `spans`: span_id -> tool_call record."""
    kind, ns, svc, agent = rec["kind"], rec["namespace"], rec["service"], rec["agent"]
    if agent is None:
        return None
    me = f"agent:{ns}/{svc}/{agent}"
    if kind == "agent_invocation":
        if rec["caller"] == "local" and rec["caller_agent"] is None:
            return edge_id("invoke", f"app:{ns}/{svc}", me)
        return None
    if kind == "model_call":
        callee = rec["callee"]
        provider = "model:mock" if callee == "mock" or callee.startswith("mock:") else "model:anthropic"
        return edge_id("model", me, provider)
    if kind in ("agent_call", "service_call", "http_call"):
        if kind == "service_call" and rec["direction"] == "inbound":
            return None
        parent = spans.get(rec["parent_span_id"])
        if parent is None:
            return "?no tool_call parent"
        tool = parent["callee"]
        if kind == "agent_call":
            target_svc, _, target_agent = rec["callee"].rpartition("/")
            target = f"agent:{ns}/{target_svc or svc}/{target_agent}"
        elif kind == "service_call":
            target = f"app:{ns}/{rec['callee'].split(' ', 1)[0]}"
        else:
            u = urlsplit(rec["callee"].split(" ", 1)[-1])
            port = f":{u.port}" if u.port and (u.scheme, u.port) not in (("https", 443), ("http", 80)) else ""
            target = f"external:{u.scheme}://{u.hostname}{port}"
        return edge_id("tool", me, target, tool)
    return None


def tool_spans(records) -> dict:
    return {r["span_id"]: r for r in records if r["kind"] == "tool_call"}


def check_drop_rule(w: World, records, where: str) -> None:
    for r in records:
        at = f"{where} ({r['service']} {r['kind']} {r['ts']})"
        P.check(
            len(json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode()) <= MAX_RECORD_BYTES,
            at,
            "larger than 64 KiB",
        )
        c = w.charter(r["namespace"], r["service"])
        if r["agent"] is None or r["direction"] == "inbound":
            continue
        agents = {a["name"] for a in c["agents"]} if c else set()
        P.check(
            r["agent"] in agents,
            at,
            f"agent {r['agent']} is not in the stored charter and the record is not inbound: "
            "the control plane drops it (design §7)",
        )


def check_records(w: World) -> None:
    recent = w.recent
    # order: strictly newest first; equal ts in reverse write order
    for i, (a, b) in enumerate(zip(recent, recent[1:], strict=False)):
        at = f"events-recent.json [{i}]/[{i + 1}]"
        P.check(a["ts"] >= b["ts"], at, f"{a['ts']} before {b['ts']}: not newest first")
        if a["ts"] == b["ts"]:
            P.check(a["service"] == b["service"], at, "equal ts across pods: write order undefined")
            P.check(rank(a) > rank(b), at, f"equal ts: {a['kind']} before {b['kind']} is not reverse write order")
    P.check(all(ts(r["ts"]) < w.generated for r in recent), "events-recent.json", "records after the graph snapshot")
    check_drop_rule(w, recent, "events-recent.json")

    # stats against the records (every record newer than the oldest one of events-recent is in it)
    oldest = ts(recent[-1]["ts"])
    window = w.generated - STATS_WINDOW
    spans = tool_spans(recent)
    by_edge = defaultdict(list)
    for r in recent:
        e = expected_edge(r, spans)
        P.check(e is None or not e.startswith("?"), f"events-recent.json ({r['kind']} {r['ts']})", f"edge: {e}")
        if e and not e.startswith("?"):
            by_edge[e].append(r)
    for eid, e in w.edges.items():
        recs = by_edge.get(eid, [])
        last = e["stats"]["last_ts"]
        if recs:
            P.check(
                last == max(r["ts"] for r in recs), eid, f"last_ts {last}, newest record {max(r['ts'] for r in recs)}"
            )
        else:
            P.check(
                last is None or ts(last) < oldest,
                eid,
                f"last_ts {last} is newer than the oldest recent record, which has none for it",
            )
        in_window = [r for r in recs if ts(r["ts"]) >= window]
        s = e["stats"]
        P.check(s["calls"] >= len(in_window), eid, f"calls {s['calls']} < {len(in_window)} records")
        P.check(s["denied"] >= sum(r["decision"] == "deny" for r in in_window), eid, "denied below the records")
        P.check(s["errors"] >= sum(r["error"] is not None for r in in_window), eid, "errors below the records")
    for eid in by_edge:
        P.check(eid in w.edges, "events-recent.json", f"records map to {eid}, which is not in graph.json")
    for nid, n in w.nodes.items():
        if n["type"] != "agent" or n.get("placeholder"):
            continue
        _, ns_svc_agent = nid.split(":", 1)
        ns, svc, agent = ns_svc_agent.split("/")
        mine = [
            r
            for r in recent
            if (r["namespace"], r["service"], r["agent"]) == (ns, svc, agent) and ts(r["ts"]) >= window
        ]
        inv = [r for r in mine if r["kind"] == "agent_invocation"]
        st = n["stats"]
        P.check(st["invocations"] >= len(inv), nid, "invocations below the records")
        P.check(
            st["denied"]
            >= sum(r["decision"] == "deny" for r in mine if r["kind"] in ("agent_invocation", "tool_call")),
            nid,
            "denied below the records",
        )
        P.check(
            st["errors"] >= sum(r["error"] is not None for r in mine if r["kind"] in ("agent_invocation", "tool_call")),
            nid,
            "errors below the records",
        )
        calls = [r for r in mine if r["kind"] == "model_call" and r["tokens"]]
        P.check(st["tokens_in"] >= sum(r["tokens"]["input"] for r in calls), nid, "tokens_in below the records")
        P.check(st["tokens_out"] >= sum(r["tokens"]["output"] for r in calls), nid, "tokens_out below the records")
    for nid, n in w.nodes.items():
        if n["type"] == "app" and not n.get("placeholder"):
            ns, svc = nid[4:].split("/")
            inbound = [
                r
                for r in recent
                if (r["namespace"], r["service"], r["kind"], r["direction"]) == (ns, svc, "service_call", "inbound")
                and ts(r["ts"]) >= window
            ]
            P.check(n["stats"]["calls"] >= len(inbound), nid, "calls below the inbound service_call records")
            P.check(
                n["stats"]["denied"] >= sum(r["decision"] == "deny" for r in inbound), nid, "denied below the records"
            )

    # learning and config records agree with proposals and charters
    for r in recent + [d["record"] for _, ev, d in w.frames if ev == "audit"]:
        at = f"{r['service']} {r['kind']} {r['ts']}"
        if r["kind"] == "learning" and r["rule"] == "learning.proposed":
            P.check(
                any(
                    p["request_id"] == r["input"]["request_id_of_run"] and p["note"] == r["output"]["note"]
                    for p in w.proposals
                ),
                at,
                "no proposal for this learning.proposed record",
            )
        if r["kind"] == "config" and r["callee"] == "charter" and r["input"]:
            name_doc = w.charters.get((r["namespace"], r["service"]))
            if name_doc and r["input"]["version"] == name_doc[1]["version"]:
                P.check(
                    r["input"]["sha256"] == sha(name_doc[1]["yaml"]) and r["input"]["epoch"] == name_doc[1]["epoch"],
                    at,
                    "sha256/epoch differ from the stored charter",
                )


def check_sse(w: World) -> None:
    frames = w.frames
    ids = [f[0] for f in frames]
    P.check(ids == sorted(set(ids)), "events.sse", "ids do not strictly increase")
    names = [f[1] for f in frames]
    graph_version = int(w.graph["version"])
    services = {(s["namespace"], s["service"]): s for s in w.services}
    instances = {i["instance_id"]: (s["namespace"], s["service"]) for s in w.services for i in s["instances"]}
    proposals = {p["id"]: p for p in w.proposals}
    versions = {k: s["charter_version"] for k, s in services.items()}
    put_sha = {}  # (ns, svc, version) -> sha256_after
    seen_records = list(w.recent)
    audit_by_service = defaultdict(list)
    for i, (fid, ev, d) in enumerate(frames):
        at = f"events.sse id {fid} ({ev})"
        prev = frames[i - 1][0] if i else None
        if ev == "reset":
            P.check(i == 0, at, "a reset starts a connection: the client then refetches")
        elif ev == "lagged":
            P.check(
                prev is not None and fid - prev >= d["dropped"],
                at,
                f"id gap {fid - (prev or 0)} below dropped {d['dropped']}",
            )
        elif ev == "graph":
            v = int(d["version"])
            P.check(v > graph_version, at, "graph versions increase")
            graph_version = v
        elif ev == "registry":
            key = (d["namespace"], d["service"])
            P.check(key in services, at, "unknown service")
            if d["status"] == "connected":
                instances[d["instance_id"]] = key
            else:
                P.check(instances.get(d["instance_id"]) == key, at, "disconnect of an unknown instance")
        elif ev == "ack":
            key = (d["namespace"], d["service"])
            P.check(instances.get(d["instance_id"]) == key, at, "ack from an unknown instance")
            want = versions.get(key) if d["kind"] == "charter" else services[key]["memory_version"]
            P.check(d["version"] == want, at, f"acks version {d['version']}, current is {want}")
            P.check(d["applied"] == (d["error"] is None), at, "applied iff no error")
        elif ev == "config":
            key = (d["namespace"], d["service"])
            old = versions.get(key)
            P.check(old is None or int(d["version"]) == int(old) + 1, at, f"version {d['version']} after {old}")
            versions[key] = d["version"]
        elif ev == "cp_audit":
            if d["action"] == "charter_put":
                key = (d["namespace"], d["service"])
                name_doc = w.charters.get(key)
                if name_doc and d["from_version"] == name_doc[1]["version"]:
                    P.check(
                        d["sha256_before"] == sha(name_doc[1]["yaml"]), at, "sha256_before is not the stored charter's"
                    )
                put_sha[(*key, d["to_version"])] = d["sha256_after"]
                nxt = next((f for f in frames[i + 1 :] if f[1] == "config"), None)
                P.check(
                    nxt is not None and nxt[2]["version"] == d["to_version"] and nxt[2]["actor"] == d["actor"],
                    at,
                    "no config event follows",
                )
            if d["action"].startswith("proposal_"):
                prior = [f for f in frames[:i] if f[1] == "proposal" and f[2]["service"] == d["service"]]
                P.check(
                    bool(prior) and prior[-1][2]["status"] == d["action"].removeprefix("proposal_") + "ed",
                    at,
                    "no matching proposal event",
                )
        elif ev == "proposal":
            p = proposals.get(d["id"])
            if p:
                P.check(p["status"] == "pending" and d["status"] != "pending", at, "a decision on a pending proposal")
                P.check(
                    {k: v for k, v in d.items() if k != "status"} == {k: v for k, v in p.items() if k != "status"},
                    at,
                    "differs from proposals.json",
                )
        elif ev == "audit":
            r = d["record"]
            P.check(ts(r["ts"]) > w.generated, at, "audit record before the graph snapshot")
            P.check((r["namespace"], r["service"]) in services, at, "unknown service")
            seen_records.append(r)
            want = expected_edge(r, tool_spans(seen_records))
            P.check(d["edge_id"] == want, at, f"edge_id {d['edge_id']}, design §10.1 says {want}")
            P.check(d["animate"] == (d["edge_id"] is not None), at, "animate iff an edge")
            if d["edge_id"] and d["edge_id"] not in w.edges:
                P.check(
                    "graph" in names[i + 1 :], at, f"{d['edge_id']} is not in graph.json and no graph event follows"
                )
            audit_by_service[(r["namespace"], r["service"])].append(r)
            if r["kind"] == "config" and r["callee"] == "charter":
                want_sha = put_sha.get((r["namespace"], r["service"], r["input"]["version"]))
                if want_sha:
                    P.check(r["input"]["sha256"] == want_sha, at, "sha256 is not the written charter's")
    check_drop_rule(w, [d["record"] for _, ev, d in frames if ev == "audit"], "events.sse")
    # per pod, audit events arrive in write order
    for key, recs in audit_by_service.items():
        for a, b in zip(recs, recs[1:], strict=False):
            P.check(
                a["ts"] < b["ts"] or (a["ts"] == b["ts"] and rank(a) < rank(b)),
                f"events.sse {key[1]}",
                f"{a['kind']} {a['ts']} then {b['kind']} {b['ts']}: not write order",
            )


def check_coverage(w: World) -> None:
    """Design §11: every UI path has data."""
    where = "coverage (design §11)"
    statuses = {s["status"] for s in w.services}
    for st in ("connected", "disconnected", "no_charter"):
        P.check(st in statuses, where, f"no service with status {st}")
    P.check(any(s["pending_adoption"] for s in w.services if s["status"] == "no_charter"), where, "no pending adoption")
    P.check(any(n.get("placeholder") for n in w.graph["nodes"]), where, "no placeholder node")
    agent_status = {n["status"] for n in w.graph["nodes"] if n["type"] == "agent" and not n.get("placeholder")}
    for st in ("ok", "idle", "errors", "denied"):
        P.check(st in agent_status, where, f"no agent with status {st}")
    P.check("model:mock" in w.nodes and "model:anthropic" in w.nodes, where, "both model providers")
    P.check(any(n["type"] == "external" for n in w.graph["nodes"]), where, "no external node")
    P.check(any(not e["declared"] for e in w.graph["edges"]), where, "no undeclared edge")
    P.check(
        any(t["allowed"] is False for n in w.graph["nodes"] if n["type"] == "agent" for t in n.get("tools", [])),
        where,
        "no tool with allowed: false (dimmed)",
    )
    P.check(w.viewer["role"] == "viewer" and w.viewer["payloads"] is False, where, "no viewer without payloads")
    P.check(
        w.validate_result["needs_role"] == "admin" and w.validate_result["weakened"],
        where,
        "the validate result needs admin and lists weakened paths",
    )
    P.check(w.links["applied"] and w.links["failed"], where, "the link result has an applied and a failed write")
    inline = not_inline = harness = learning = False
    for _name, doc in w.charters.values():
        c = doc["charter"]
        skills = {s["name"]: s for s in c.get("skills", [])}
        for a in c["agents"]:
            for s in a.get("skills", []):
                size = len(skills[s]["instructions"].encode())
                inline |= size < INLINE_SKILL_BYTES
                not_inline |= size >= INLINE_SKILL_BYTES
            harness |= "harness" in a
            lrn = a.get("learning") or {}
            learning |= lrn.get("enabled") is True and lrn.get("mode", "review") == "review"
    P.check(inline and not_inline, where, "an agent with an inline skill and one loaded with load_skill")
    P.check(harness, where, "an agent with a harness")
    P.check(learning, where, "an agent with learning enabled in review mode")
    P.check(any(w.memory["agents"].values()), where, "no notes")
    P.check(any(p["status"] == "pending" for p in w.proposals), where, "no pending proposal")
    kinds = {r["kind"] for r in w.recent} | {d["record"]["kind"] for _, ev, d in w.frames if ev == "audit"}
    for k in (
        "config",
        "learning",
        "agent_invocation",
        "model_call",
        "tool_call",
        "agent_call",
        "service_call",
        "guardrail",
    ):
        P.check(k in kinds, where, f"no audit record of kind {k}")
    P.check(any(r["callee"].startswith("load_skill:") for r in w.recent), where, "no load_skill record")
    events = {ev for _, ev, _ in w.frames}
    for ev in ("audit", "graph", "registry", "config", "ack", "proposal", "cp_audit", "lagged", "reset"):
        P.check(ev in events, where, f"events.sse has no {ev} event")
    P.check(any(ev == "ack" and d["applied"] is False for _, ev, d in w.frames), where, "no failed ack")
    P.check(any(ev == "ack" and d["applied"] is True for _, ev, d in w.frames), where, "no applied ack")
    P.check(any(ev == "audit" and d["animate"] for _, ev, d in w.frames), where, "no animated audit event")
    P.check(
        w.whoami["payloads"] is True and w.whoami["role"] == "admin",
        where,
        "whoami: an admin who sees payloads (cp_audit)",
    )


def run_all(src: Source, attache: Path | None) -> Problems:
    """Every check over `src`; the problems found."""
    global P, SRC
    P, SRC = Problems(), src
    check_openapi(src.doc, src.design)
    check_schemas(src.doc)
    w = World()
    check_ids(w)
    check_graph(w)
    check_documents(w)
    run_cli_validate(w, attache)
    check_records(w)
    check_sse(w)
    check_coverage(w)
    return P


# ---- self-test: each mutation must be reported -------------------------------------------------


def _json_edit(name: str, edit):
    def mutate(src: Source) -> None:
        data = json.loads(src.files[name])
        edit(data)
        src.files[name] = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    return mutate


def _sse_edit(event_name: str, edit, nth: int = 0):
    """Edit the `data` of the nth event named `event_name` in events.sse."""

    def mutate(src: Source) -> None:
        blocks = src.files["events.sse"].split("\n\n")
        seen = 0
        for i, block in enumerate(blocks):
            if f"\nevent: {event_name}\n" in f"\n{block}\n":
                if seen == nth:
                    head, _, data = block.partition("data: ")
                    d = json.loads(data)
                    edit(d)
                    blocks[i] = head + "data: " + json.dumps(d, separators=(",", ":"), ensure_ascii=False)
                    break
                seen += 1
        src.files["events.sse"] = "\n\n".join(blocks)

    return mutate


def _recent_find(data, kind, service, nth=0):
    return [i for i, r in enumerate(data) if r["kind"] == kind and r["service"] == service][nth]


def _swap_tie(data):
    i = _recent_find(data, "service_call", "support")
    data[i], data[i + 1] = data[i + 1], data[i]


def _inbound_to_outbound(data):
    data[_recent_find(data, "service_call", "inventory")]["direction"] = "outbound"


def _doc_edit(edit):
    def mutate(src: Source) -> None:
        edit(src.doc)

    return mutate


def _op(doc, path, method):
    return doc["paths"][path][method]


def _drop_node(node_id):
    return _json_edit("graph.json", lambda g: g.__setitem__("nodes", [n for n in g["nodes"] if n["id"] != node_id]))


def _sse_ids(src: Source) -> None:
    src.files["events.sse"] = src.files["events.sse"].replace("id: 48262\n", "id: 48240\n")


MUTATIONS = [
    ("equal ts not in reverse write order", _json_edit("events-recent.json", _swap_tie), "reverse write order"),
    ("events-recent not newest first", _json_edit("events-recent.json", lambda d: d.reverse()), "not newest first"),
    ("an inbound record made outbound", _json_edit("events-recent.json", _inbound_to_outbound), "drops it (design §7)"),
    ("SSE edge_id off the mapping", _sse_edit("audit", lambda d: d.__setitem__("edge_id", None)), "design §10.1 says"),
    (
        "SSE animate without an edge",
        _sse_edit("audit", lambda d: d.__setitem__("animate", False)),
        "animate iff an edge",
    ),
    ("a span id too short", _json_edit("events-recent.json", lambda d: d[0].__setitem__("span_id", "abc")), "span_id"),
    ("an unknown node field", _json_edit("graph.json", lambda g: g["nodes"][0].__setitem__("colour", "red")), "schema"),
    ("a placeholder removed", _drop_node("agent:attache-demo/billing/refund-approver"), "is not a node"),
    (
        "a stale edge last_ts",
        _json_edit("graph.json", lambda g: g["edges"][0]["stats"].__setitem__("last_ts", "2026-10-21T09:00:00.000Z")),
        "last_ts",
    ),
    (
        "a service status off its instances",
        _json_edit("services.json", lambda s: s[-1].__setitem__("status", "degraded")),
        "status",
    ),
    (
        "notes for an agent without learning",
        _json_edit("memory.json", lambda m: m["agents"].__setitem__("faq", m["agents"]["support-agent"])),
        "no learning enabled",
    ),
    ("a lagged event without its id gap", _sse_ids, "id gap"),
    (
        "adoption checked on the diff",
        _doc_edit(lambda d: _op(d, "/services/{ns}/{svc}/adopt", "post").__setitem__("x-role-on-diff", True)),
        "adopt has no stored charter",
    ),
    (
        "logout without 400",
        _doc_edit(lambda d: _op(d, "/logout", "post")["responses"].pop("400")),
        "does not document 400",
    ),
    (
        "agent delete not on the diff",
        _doc_edit(lambda d: _op(d, "/services/{ns}/{svc}/agents/{agent}", "delete").pop("x-role-on-diff")),
        "x-role-on-diff",
    ),
    (
        "a role off the design table",
        _doc_edit(lambda d: _op(d, "/services/{ns}/{svc}/memory", "put").__setitem__("x-required-role", "admin")),
        "design §10 says",
    ),
    (
        "the mapping not quoted",
        _doc_edit(lambda d: d["components"]["schemas"]["Edge"].__setitem__("description", "")),
        "record → edge mapping",
    ),
    (
        "the drop rule not quoted",
        _doc_edit(lambda d: d["components"]["schemas"]["AuditRecord"].__setitem__("description", "")),
        "drop rule",
    ),
    (
        "a dangling $ref",
        _doc_edit(
            lambda d: d["components"]["schemas"]["Graph"]["properties"]["nodes"]["items"].__setitem__(
                "$ref", "#/components/schemas/Nope"
            )
        ),
        "does not resolve",
    ),
    (
        "strict audit directions",
        _doc_edit(
            lambda d: d["components"]["schemas"]["AuditRecord"]["properties"]["direction"].__setitem__(
                "enum", ["inbound"]
            )
        ),
        "must be any string",
    ),
    (
        "a proposal event that differs",
        _sse_edit("proposal", lambda p: p.__setitem__("note", "x")),
        "differs from proposals.json",
    ),
    (
        "a charter put without its sha",
        _sse_edit("cp_audit", lambda c: c.__setitem__("sha256_before", "0" * 64)),
        "sha256_before",
    ),
]


def self_test(attache: Path | None) -> int:
    base = Source.from_disk(FIXTURES)
    clean = run_all(base, attache)
    failed = []
    if clean.items:
        failed.append(f"the committed fixtures have {len(clean.items)} problems; run without --self-test")
    for name, mutate, want in MUTATIONS:
        src = Source(dict(base.files), json.loads(json.dumps(base.doc)), base.design)
        mutate(src)
        try:
            found = run_all(src, None).items
        except Exception as e:  # a crash is not a report
            found = [f"crashed: {type(e).__name__}: {e}"]
        if not any(want in p for p in found):
            failed.append(f"{name}: no problem mentions {want!r}; got {found[:3]}")
    for f in failed:
        print(f"self-test: {f}")
    print(f"self-test: {len(MUTATIONS) - len(failed)} of {len(MUTATIONS)} mutations reported")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--attache", type=Path, help="the attache CLI (default: target/debug/attache when built)")
    ap.add_argument("--fixtures", type=Path, default=FIXTURES, help="the fixture directory (default: ui/fixtures)")
    ap.add_argument(
        "--self-test", action="store_true", help="also check that known-bad edits of the fixtures are reported"
    )
    args = ap.parse_args()
    attache = args.attache or (REPO / "target" / "debug" / "attache")
    if not attache.exists():
        if args.attache:
            print(f"--attache {attache}: no such file")
            return 2
        attache = None
    if attache is None:
        print(
            "note: target/debug/attache is not built; `attache charter validate` is skipped "
            "(the JSON Schema check runs)"
        )

    src = Source.from_disk(args.fixtures)
    problems = run_all(src, attache)
    if problems.items:
        for p in problems.items:
            print(p)
        print(f"FAILED: {len(problems.items)} of {problems.checks} checks")
        return 1
    print(f"ok: {problems.checks} checks over {len(src.files)} files in {args.fixtures}")
    if args.self_test:
        return self_test(attache)
    return 0


if __name__ == "__main__":
    sys.exit(main())
