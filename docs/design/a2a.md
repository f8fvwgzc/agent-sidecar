# A2A: serving agents to, and calling agents of, other organisations

Status: implemented in v1 (charter schema level 10). Decision record:
[ADR 0010](../adr/0010-a2a.md). Normative text: CONTRACT.md §3.1 (`a2a` tools), §4.5 (the A2A
server), §5.2 (taint).

## Why

[A2A](https://a2a-protocol.org/latest/specification/) 1.0 is the Agentic AI Foundation's
agent-to-agent protocol: an agent publishes a card, other agents send it messages, and long
work becomes a task with states. attache agents already call each other, but only inside the
mesh (gRPC over mTLS, CONTRACT.md §4.2). A2A is how they reach agents outside it, and how agents
outside it reach them, without a bespoke API per partner.

Like Dapr, attache keeps its own protocol inside and speaks the open one at the edge: A2A is a
separate listener for callers outside the mesh and a tool type for calls out of it. Inside the
mesh nothing changes.

## Inbound: the sidecar as an A2A server

Off unless `--a2a-addr` is set; then every agent with an `a2a` block is served.

| A2A                                   | attache                                                        |
| ------------------------------------- | -------------------------------------------------------------- |
| Agent card                            | Made from `agents[].a2a` (description, skills); never the system prompt, tools or policy |
| Security scheme `Bearer`              | A token file per caller in `--a2a-callers-dir`; the caller is `a2a:<file name>` |
| Who may call                          | `authz.callers` rules with identity `a2a:<name>`, as for any caller |
| `SendMessage`                         | An invocation through the whole pipeline (CONTRACT.md §4.1)    |
| Text parts / data parts               | `input` / `context`; file parts are refused                    |
| `TASK_STATE_INPUT_REQUIRED`           | A run that asked the caller (`ask_caller`, agent practices)    |
| The next message with that `taskId`   | The answer: the agent runs again with `context.answers`        |
| `COMPLETED` / `REJECTED` / `FAILED`   | Status `ok` / `denied` / `error`                               |
| `GetTask`, `CancelTask`               | The caller's own tasks, in memory for an hour                  |

Decisions:

1. **The caller is an identity, so the existing authz applies.** A token names a caller
   (`a2a:partner`), and `authz.callers` decides which agents it reaches, with the same rule
   names and records as for a mesh peer. Adding or removing an `a2a` block is an admin change;
   adding an `authz.callers` rule already was.
2. **A2A input is untrusted.** The text comes from another party's agent. The run starts with
   the `untrusted` label whatever `taint.input` says, and the charter requires a `taint` block
   on a served agent, so `taint.untrusted_write` holds back write tools after it.
3. **Questions are tasks.** The runtime is stateless and an app answers questions by invoking
   again with the answers in `context` (CONTRACT.md §4.1). The A2A server does exactly that on
   the caller's behalf: it keeps the first message and the answers so far, and invokes the
   agent again when the caller replies to the task. One invocation is still one policy decision.
4. **Static tokens, read per request.** No OAuth or mTLS for outside callers in v1: a mounted
   Secret per caller, rotated by replacing the file. Every caller's file is compared, in
   constant time, so the time does not tell which callers exist.
5. **Synchronous runs, no streaming.** `SendMessage` returns when the run ends; the card says
   `streaming: false`, `pushNotifications: false`. Tasks live in memory, so a restart forgets
   them; durable tasks are later work (Dapr Workflows' idea, the SQLite store).
6. **Plain HTTP, TLS in front.** The sidecar's certificates are mesh identities, not public
   names, so TLS is the ingress's or gateway's job (agentgateway, Agent Router or any ingress).

## Outbound: `type: a2a` tools

```yaml
- name: partner_quotes
  type: a2a
  description: Quotes from the partner's agent.
  url: https://agents.partner.example/a2a/quotes
  credential: {secret: partner}
```

Decisions:

1. **The sidecar is the client; the runtime sends `input`, `context` and `task_id`.** As for MCP
   tools, the URL, headers and token come from the charter. The parameters are fixed, so a
   charter cannot widen them.
2. **Egress like `http` and `mcp`.** Default `label: untrusted`, `effect: write`;
   `taint.sensitive_egress`, the origin allowlist and new-origin roles apply.
3. **Input-required is the model's to answer.** The rendered result names the `task_id`; the
   model answers with another call. No state is kept in the sidecar between calls.
4. **Working tasks are polled** with `GetTask` (250 ms doubling to 4 s) until the run budget of
   the call (`RUN_TIMEOUT`, or the caller's deadline) runs out.
5. **No card fetch.** The charter names the endpoint an admin reviewed; the remote card's
   descriptions never reach the model. Verifying signed cards is later work.

Records: a `tool_call` and an `a2a_call` (callee `a2a <origin>`), spans named
`invoke_agent <host>` with `gen_ai.operation.name: invoke_agent`. Embassy draws the remote agent
as an external node, counts the call as egress in risk features, and the console shows `a2a`
edges, ports and timeline bars.

## Later

- Signed agent cards (JWS over the RFC 8785 form, A2A §8.4) with a key embassy's CA vouches for,
  and verifying a remote card's signature before a tool uses it.
- OAuth 2.0 / OIDC bearer tokens and mTLS for A2A callers.
- Streaming, push notifications and durable tasks.
- The gRPC and HTTP+JSON bindings.
