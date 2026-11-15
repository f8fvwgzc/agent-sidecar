# 9. MCP tools: the sidecar is the MCP client, and every tool is pinned

Status: implemented
Date: 2026-11-07

## Context

Agents had three kinds of tools: `service`, `agent` and `http`. Most tools teams want to give an
agent now ship as MCP servers (GitHub, Jira, databases, internal platforms), and rebuilding each
one as an `http` tool works only where the server also has a REST API. Hosts that speak MCP
directly put every tool a server lists in front of the model, with the server's own
descriptions, which the server can change later (a "rug pull"); nothing checks a call against a
policy or tracks what a run has read.

MCP's 2026-07-28 revision removed sessions and `initialize`: a `tools/call` is one stateless
POST that carries its protocol version in `_meta` and in headers. One call can be one policy
decision, like every other tool call. The full design is
[docs/design/mcp-tools.md](../design/mcp-tools.md).

## Decision

1. **A fourth tool type, `type: mcp`** (charter schema level 9): `url` (the server's MCP
   endpoint), `mcp_tool` (the server's name, default `name`), a required `pin`, and the
   `parameters` the model sees, which are required and may be narrower than the server's
   `inputSchema`. Only protocol 2026-07-28 over Streamable HTTP; no stdio servers and no older
   revisions.
2. **The sidecar is the MCP client; the runtime sends only arguments.** A new RPC
   `SidecarTools.InvokeMcp(ToolArgumentsRequest{ctx, arguments_json}) → ToolTextResponse{text, is_error}`
   (named `ToolMcpRequest` / `McpResponse` until ADR 0010 shared them with `InvokeA2a`).
   The sidecar builds the URL, `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, the
   `Mcp-Param-*` headers and the bearer token from the charter, and reads a JSON or SSE answer
   up to `--max-response-bytes`.
3. **Pinned definitions.** `pin` is `sha256:` and the hex SHA-256 of the RFC 8785 canonical
   JSON of the server's `description`, `inputSchema`, `outputSchema` and `annotations`. The
   sidecar keeps each server's `tools/list` for `min(ttlMs, 600 s)` and refuses a call while
   the server lists another definition (`mcp.pin_mismatch`) or none, or one whose
   `x-mcp-header`s break MCP's rules (`mcp.tool_missing`). A refusal names hashes, never the new
   text.
4. **Narrowed arguments.** The arguments are validated against the charter's `parameters`
   (the `jsonschema` crate, without its network features and with a retriever that refuses
   every external `$ref`) before anything is sent; a failure is `guardrail.tool_spec`.
5. **The same gates as `http`, in the same order**: bind, tool match, argument check, taint,
   quarantine, approval, delegation. An `mcp` tool defaults to `label: untrusted` and
   `effect: write`; `taint.sensitive_egress` covers `mcp` tools. An approval is MCP's "human in
   the loop with the ability to deny tool invocations".
6. **Credentials**: `delegation` as for `http` (ADR 0006), or `credential: {secret}`, a file in
   the sidecar's `--tool-secrets-dir` (default `/etc/agentsc/tool-secrets`) read on every call.
   The charter names a DNS-1123 label, never a path, so it cannot make the sidecar send another
   file (`tls.key`) to a server it names. Neither token is logged or audited.
7. **Records**: a `tool_call` and a new kind `mcp_call` (callee `mcp <origin> <mcp_tool>`,
   input `{url, tool, arguments}`, output `{result_type, is_error, text}`); spans are named
   `tools/call <tool>` with the OTel MCP attributes.
8. **Tooling**: `agentsc mcp import` prints pinned entries, with annotations only as commented
   suggestions (MCP says they are untrusted); `agentsc mcp check` exits 1 on drift, for CI.
9. **Roles**: a new MCP origin, a changed `pin`, `mcp_tool` or `parameters` of a declared tool,
   and any `credential` change need admin. The MCP client lives in `agentsc-common`
   (`mcp_client`), shared by the sidecar and the CLI; pins, header rules and the argument
   validator live in `agentsc-charter` (`mcp`).

## Consequences

- A server that changes a tool stops that tool until an admin reviews the change and pins it
  again (`agentsc mcp check`, then a new `pin`). That is the point, and it costs a round of
  review per server update.
- One extra `tools/list` per server per cache period, made with the bearer of the call that
  refreshes it; a delegated tool's list is fetched with the first caller's token.
- Servers that speak only 2025-11-25 or older fail with `mcp.unsupported_version`; a fallback
  with sessions would be per-server state that outlives one policy decision, and is left out.
- An `input_required` answer (elicitation, sampling) is a tool error the model sees; mapping it
  to `ask_caller` questions and retrying with `inputResponses` is later work.
- `agentscd` gains a JSON Schema validator; `agentsc-common` gains `reqwest`, and the CLI
  `tokio` and `reqwest`.

## Alternatives

- **Hand every listed tool to the model, as MCP hosts do.** The server would write the prompt,
  and could rewrite it at any time.
- **A central MCP gateway (agentgateway and the like).** It cannot apply the taint rules, which
  need what each run has read, and it would be one more hop outside the sidecar's records.
- **The runtime as MCP client, with `InvokeHttp`.** The runtime is driven by a model; it would
  choose headers and the body, and the sidecar would have to re-parse MCP to check them.
- **Pinning the whole definition, `title` and `icons` included.** A cosmetic change would stop
  the tool for nothing a model or a call depends on.
- **Credentials at any path the charter names.** A charter could point the sidecar at its own
  TLS key and send it to a server of its choosing.
