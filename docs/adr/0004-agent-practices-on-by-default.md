# 4. Agent practices on by default, fixed in the runtime

Status: implemented
Date: 2026-10-27

## Context

Every team that ran an agent wrote the same advice into its `system` prompt: plan before you
act, look facts up instead of guessing, ask when you are stuck, and don't waste tokens. Each team
worded it differently, some forgot it, and none of it was versioned or tested. The texts that
work best come from outside the project (learnharness, the `grilling` and `caveman` skills,
Harness²), and copying them into each charter would have spread one more unreviewed prompt per
agent.

Two parts of the platform made this harder than adding a paragraph:

1. **Callers are programs.** An app or another agent calls an agent, not a person in a chat.
   An agent that wants a decision from its caller has no turn to ask in, and the response
   envelope (CONTRACT §4.1) knows three statuses, `ok`, `denied` and `error`, which apps and
   peer sidecars already branch on.
2. **Learning had no evidence.** A reflection turned a run into one line of free text. Nothing
   tied the note to what happened in the run, so a reviewer could not check it, and nothing
   said whether it was about how to work or about the agent's subject.

The design is in [docs/design/agent-practices.md](../design/agent-practices.md); the contract
is CONTRACT §3, §3.2, §3.3, §3.5, §4.1, §4.3 and §9.

## Decision

- **Practices are on by default, and their texts live in the runtime.** `plan`, `clarify` and
  `brevity` (with `agent_brevity` and `auto_clarity`) are fixed, versioned texts that the
  runtime puts in the system prompt under `# Working method` and `# Output style`. The charter
  block `agents[].practices` (schema level 6) holds only switches, levels and
  `max_questions`, never text, so a charter edit can't use it to carry instructions. An absent
  block means every practice on; an author who wants other words writes them in `system` or in
  a skill.
- **Questions keep status `ok` and add a field.** `clarify` offers the runtime tool
  `ask_caller`. A valid call ends the run with status `ok`, an `output` that holds the questions
  as text, and an additive `questions` list (`{question, recommended}`) in the HTTP response,
  `InvokeAgentResponse` and `ExecuteResponse`. A non-`ok` status never carries questions. The
  caller answers in its next invocation: an app in `context`, an agent caller, which has only
  `input`, in `input`. The sidecar treats the questions as
  model output: dropped under `clarify: never`, capped at `max_questions`, run through
  `output_deny` as the runtime sent them, PII redaction, the cut, and `output_deny` again as
  delivered, and audited with rule `clarify.asked`. It renders `output` from the questions it
  keeps and checks that too, so the audit log shows exactly what the caller got, and the
  caller gets only checked text.
- **No value is `off`.** `clarify` is `never | blocking | always`, and `brevity` and
  `agent_brevity` are `normal | lite | full | ultra`. YAML 1.1 readers (`kubectl`, Helm's
  `fromYaml`, PyYAML) read a bare `off` as the boolean `false`, so a charter that said
  `clarify: off` would fail validation once it went through one of them.
- **The brevity level follows the caller's kind.** `brevity` (default `lite`) applies when the
  service's own app (or another local caller without a calling agent) is the caller,
  `agent_brevity` (default `full`) when the Execute has a `caller_agent`. Every call over the
  mesh comes from an agent tool, so it gets `agent_brevity`. Apps often show the answer to
  people; agents only read it.
- **Lessons cite their evidence.** The reflection's transcript numbers each step, the answer
  is four lines (`SCOPE`, `TARGET`, `EVIDENCE`, `NOTE`), and code, not the model, checks it: an
  unknown step id, a scope the charter doesn't keep or a note over `max_note_chars` gives no
  lesson. The reflection sees payload-free digests of earlier runs to contrast against. Only
  the note becomes memory; the rest goes to the reviewer in the `rationale`.
- **Learning stays off by default.** The three new `learning` fields default to
  `require_evidence: true`, `contrast_runs: 5` and both scopes, but matter only when
  `learning.enabled` is true, and `enabled` still defaults to false.
- **No self-edit and no probe rollouts.** A lesson's `TARGET` (`system`, `skill:<name>`,
  `tool:<name>`) is advice for the reviewer. Nothing edits the prompt, a skill or policy on its
  own, and nothing re-runs a task to test a lesson.

## Consequences

- Every agent gets the practices on the first level-6 sidecar, without a charter change. In a
  mixed fleet the same agent behaves differently on an older sidecar (level 5 or below) and a
  level-6 sidecar until all are upgraded; the sidecar and the runtime ship in one image, so they always agree on
  `agent_spec_json`.
- The opt-out is a level-6 `practices` block. The control plane refuses it (400) while an
  older sidecar of the service is connected, and an older sidecar rejects it in a ConfigMap
  charter, so it can be written only after the last old pod is gone. Until then the upgraded
  pods run the defaults, and an unattended app treats a response with `questions` as not
  final.
- A tool named `ask_caller` is rejected at every level, so a charter with one renames it
  before the upgrade.
- Old apps and peers keep working: a run that asked is `ok`, and its `output` already shows the
  questions. An app that runs unattended and can't answer sets `clarify: never`, or passes the
  recommended answers back in `context`. Answers in `context` (or the input) are vouched for by
  the caller, and the answering run starts with only `taint.input` (CONTRACT §5.2). So for an
  agent with a `taint` block an unattended app must not send the recommended answers back on
  its own, since they may come from untrusted data: it uses `clarify: never` for that agent,
  or a person answers.
- Each practice costs input tokens on every model call, and the plan costs a few output tokens
  before the first tool call, which count against `max_tokens_per_call`.
- Brevity rewrites the answer, so an `output_deny` pattern that expects full sentences may stop
  matching. Teams test their patterns at the level they use.
- The practices are instructions, not enforcement. The sidecar still enforces tools, budgets,
  guardrails and taint; `ask_caller` adds no permission, it only ends the run.
- Two changes count as weakening (`diff::weakened`): `practices.auto_clarity` and
  `learning.require_evidence` from true to false. Every new field is editor-level.
- A reviewer can check a lesson against the steps it cites, and sees whether it is about how
  to work (`invariant`) or the subject (`domain`).
- Digests of earlier runs are in memory, per runtime process and replica, and reset on restart.

## Alternatives

- **Texts in the charter.** Lets each team tune the words, but a field that holds prompt text
  is a second `system`, outside the review the platform gives fixed texts, and a way for a
  charter edit to carry instructions under a harmless name. Authors who need other words
  already have `system` and skills.
- **Practices off by default.** No behaviour change on upgrade, but most agents would never get
  them, and that is the problem this decision exists to fix. A switch per practice keeps the
  opt-out one line.
- **A new status `needs_input` for questions.** Clearer on the wire, but every app, every peer
  sidecar and the gRPC status mapping branch on the three statuses today. An older peer would
  treat the new status as an error and drop the questions. Status `ok` with an additive field
  degrades to an answer that shows the questions.
- **Learning on by default.** Each qualifying run would cost a reflection model call, and
  memory counts against the per-service limit: the sum of `max_notes × max_note_chars` over the
  agents with learning on is at most `MAX_MEMORY_CHARS` (262144), so the defaults (20 × 500)
  would refuse every charter with more than 26 agents. Memory is also governed state: a team
  should choose review or `auto` on purpose.
- **Harness²-style self-edit.** Harness² lets the model rewrite its system prompt, skills,
  guardrails and plugins, and adopts the result. Here a model-authored change to instructions
  or policy needs a person and a role check (design §15 rules 5 and 7), so the lesson's
  `TARGET` stays advice and the change is a normal charter edit.
- **Probe rollouts.** Re-running a task to test a lesson would repeat its side effects on a
  live service (a refund, a ticket, a write to another pod). Contrast with digests of earlier
  runs gives the reflection something to compare against without running anything.
- **`off` as the value, quoted.** Shorter, and the word most people reach for, but every author
  would have to remember the quotes in a `Charter` resource and in Helm values, and the CRD and
  `agentsc charter to-cr` would need a writer that quotes YAML 1.1 booleans. `never` and
  `normal` read the same in YAML 1.1 and 1.2.
- **One brevity level for every caller.** `full` is too terse for answers shown to people;
  `lite` wastes tokens between agents. The Execute already says whether an agent called.
