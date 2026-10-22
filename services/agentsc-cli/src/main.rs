//! `agentsc` — the CLI (CONTRACT.md §8).
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use agentsc_charter::Charter;
use agentsc_common::audit::AuditRecordView;
use clap::{Parser, Subcommand};

/// An audit record (CONTRACT.md §6) as any sidecar version wrote it: `kind`, `direction` and
/// `decision` are kept as written, so a record of a kind this CLI does not know (from a newer
/// sidecar) is shown as-is, never dropped.
type LogRecord = AuditRecordView;

const V01_KINDS: [&str; 9] = [
    "agent_invocation",
    "model_call",
    "tool_call",
    "agent_call",
    "service_call",
    "http_call",
    "authz",
    "guardrail",
    "budget",
];

/// A record and the JSON text it was read from (what `--raw` prints, unchanged).
struct LogLine {
    rec: LogRecord,
    json: String,
}

#[derive(Parser)]
#[command(
    name = "agentsc",
    version,
    about = "agentsc: governed AI agents as a sidecar of your service"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Work with charter.yaml files.
    Charter {
        #[command(subcommand)]
        cmd: CharterCmd,
    },
    /// Tail and pretty-print the audit log of a service's sidecar.
    Logs(LogsArgs),
    /// Print the version.
    Version,
}

#[derive(Subcommand)]
enum CharterCmd {
    /// Validate a charter (plain or custom resource form); exit 1 with one error per line when invalid.
    Validate { file: std::path::PathBuf },
    /// Print the JSON Schema for charter.yaml.
    Schema {
        /// Print the CustomResourceDefinition charters.agentsc.io (YAML) instead.
        #[arg(long)]
        crd: bool,
    },
    /// Print a charter as a `Charter` custom resource (metadata from `service`, the rest in `spec`).
    ToCr { file: std::path::PathBuf },
}

#[derive(clap::Args)]
struct LogsArgs {
    /// Service name(s), comma-separated (label agentsc.io/service). Ignored with --file.
    #[arg(default_value = "")]
    service: String,
    #[arg(short = 'n', long, default_value = "agentsc-demo")]
    namespace: String,
    /// kubeconfig context (default: kubectl's current context).
    #[arg(long)]
    context: Option<String>,
    /// Only records of this agent.
    #[arg(long)]
    agent: Option<String>,
    /// Only records of this trace id.
    #[arg(long)]
    trace: Option<String>,
    /// Only records of this request id.
    #[arg(long)]
    request: Option<String>,
    /// Only records of this kind (agent_invocation, model_call, tool_call, agent_call, service_call, http_call, authz, guardrail, budget, config, learning, or any other kind a sidecar writes).
    #[arg(long)]
    kind: Option<String>,
    /// Only records whose rule starts with this (e.g. `taint.would_deny`).
    #[arg(long)]
    rule: Option<String>,
    /// Only denials.
    #[arg(long)]
    denied: bool,
    /// Follow (kubectl logs -f).
    #[arg(short, long)]
    follow: bool,
    /// Print raw JSON lines instead of the table.
    #[arg(long)]
    raw: bool,
    /// Read records from a file ("-" = stdin) instead of kubectl.
    #[arg(long)]
    file: Option<String>,
    /// How many lines kubectl should fetch per container.
    #[arg(long, default_value = "1000")]
    tail: u32,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Charter {
            cmd: CharterCmd::Validate { file },
        } => match Charter::load(&file) {
            Ok(c) => {
                println!(
                    "valid: {} ({} agent(s), identity {})",
                    file.display(),
                    c.agents.len(),
                    c.spiffe_id()
                );
                0
            }
            Err(e) => {
                eprintln!("invalid: {}\n{e}", file.display());
                1
            }
        },
        Cmd::Charter {
            cmd: CharterCmd::Schema { crd: true },
        } => {
            print!("{}", agentsc_charter::crd::crd_yaml());
            0
        }
        Cmd::Charter {
            cmd: CharterCmd::Schema { crd: false },
        } => match serde_json::to_string_pretty(&agentsc_charter::json_schema()) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        },
        Cmd::Charter {
            cmd: CharterCmd::ToCr { file },
        } => match Charter::load(&file).and_then(|c| c.to_resource().to_yaml()) {
            Ok(yaml) => {
                print!("{yaml}");
                0
            }
            Err(e) => {
                eprintln!("invalid: {}\n{e}", file.display());
                1
            }
        },
        Cmd::Logs(args) => match logs(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        },
        Cmd::Version => {
            println!("agentsc {}", env!("CARGO_PKG_VERSION"));
            0
        }
    };
    std::process::exit(code);
}

fn logs(args: LogsArgs) -> anyhow::Result<()> {
    let mut kubectl: Option<std::process::Child> = None;
    let reader: Box<dyn BufRead> = match &args.file {
        Some(f) if f == "-" => Box::new(BufReader::new(std::io::stdin())),
        Some(f) => Box::new(BufReader::new(std::fs::File::open(f)?)),
        None => {
            if args.service.is_empty() {
                anyhow::bail!("usage: agentsc logs <service> [--agent A] [--trace T] [-f]");
            }
            let mut cmd = Command::new("kubectl");
            if let Some(ctx) = &args.context {
                cmd.args(["--context", ctx]);
            }
            let selector = if args.service.contains(',') {
                format!("agentsc.io/service in ({})", args.service)
            } else {
                format!("agentsc.io/service={}", args.service)
            };
            cmd.args([
                "logs",
                "-n",
                &args.namespace,
                "-l",
                &selector,
                "-c",
                "agentscd",
                "--tail",
                &args.tail.to_string(),
                "--prefix=false",
            ]);
            if args.follow {
                cmd.arg("-f");
            }
            let mut child = cmd
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| anyhow::anyhow!("cannot run kubectl: {e}"))?;
            let stdout = child.stdout.take().expect("piped stdout");
            kubectl = Some(child);
            Box::new(BufReader::new(stdout))
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut records: Vec<LogLine> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        let json_start = match trimmed.find('{') {
            Some(i) => i,
            None => continue,
        };
        let json = &trimmed[json_start..];
        let Ok(rec) = LogRecord::from_json(json) else {
            continue;
        };
        if let Some(a) = &args.agent
            && rec.agent.as_deref() != Some(a)
            && rec.caller_agent.as_deref() != Some(a)
        {
            continue;
        }
        if let Some(t) = &args.trace
            && !rec.trace_id.starts_with(t.as_str())
        {
            continue;
        }
        if let Some(r) = &args.request
            && !rec.request_id.starts_with(r.as_str())
        {
            continue;
        }
        if let Some(k) = &args.kind
            && &rec.kind != k
        {
            continue;
        }
        if let Some(r) = &args.rule
            && !rec
                .rule
                .as_deref()
                .is_some_and(|x| x.starts_with(r.as_str()))
        {
            continue;
        }
        if args.denied && rec.decision != "deny" {
            continue;
        }
        let entry = LogLine {
            rec,
            json: json.to_string(),
        };
        if args.follow {
            print_record(&mut out, &entry, args.raw)?;
        } else {
            records.push(entry);
        }
    }
    // Without --follow, kubectl returns one pod's log after another: sort by time so a trace reads top to bottom.
    records.sort_by(|a, b| a.rec.ts.cmp(&b.rec.ts));
    for entry in &records {
        print_record(&mut out, entry, args.raw)?;
    }
    // An empty table must mean "no records", never "kubectl failed".
    if let Some(mut child) = kubectl {
        let status = child.wait()?;
        if !status.success() {
            anyhow::bail!("kubectl logs failed ({status}); no audit records were read");
        }
    }
    Ok(())
}

fn print_record(out: &mut impl Write, entry: &LogLine, raw: bool) -> anyhow::Result<()> {
    if raw {
        writeln!(out, "{}", entry.json)?;
        return Ok(());
    }
    let rec = &entry.rec;
    let ts = rec.ts.get(11..23).unwrap_or(&rec.ts);
    let kind = &rec.kind;
    let dir = &rec.direction;
    let caller = short_id(&rec.caller);
    let caller = match &rec.caller_agent {
        Some(a) if rec.kind != "agent_invocation" || rec.caller != "local" => {
            format!("{caller} ({a})")
        }
        _ => caller,
    };
    // The v0.1 kinds show an allow's rule only for PII redaction and taint audit mode; `config`,
    // `learning` and any kind this CLI does not know show the decision and rule as written.
    let v01_kind = V01_KINDS.contains(&rec.kind.as_str());
    let decision = match (rec.decision.as_str(), &rec.rule) {
        ("deny", rule) => format!("DENY {}", rule.clone().unwrap_or_default()),
        ("allow", Some(r))
            if r.starts_with("guardrail.pii") || r.starts_with("taint.") || !v01_kind =>
        {
            format!("allow {r}")
        }
        ("allow", _) => "allow".to_string(),
        (other, Some(r)) => format!("{other} {r}"),
        (other, None) => other.to_string(),
    };
    let extra = match (&rec.tokens, rec.cost_usd) {
        (Some(t), Some(c)) if t.input.saturating_add(t.output) > 0 => {
            format!(" tokens={}/{} ${:.4}", t.input, t.output, c)
        }
        _ => String::new(),
    };
    let err = rec
        .error
        .as_ref()
        .map(|e| format!(" error={e}"))
        .unwrap_or_default();
    writeln!(
        out,
        "{ts} {:<10} {:<14} {:<16} {:<8} {:<28} → {:<34} {:<40} {:>6}ms{extra}{err} trace={}",
        rec.service,
        rec.agent.clone().unwrap_or_else(|| "-".into()),
        kind,
        dir,
        truncate(&caller, 28),
        truncate(&rec.callee, 34),
        decision,
        rec.latency_ms,
        rec.trace_id.chars().take(8).collect::<String>(),
    )?;
    Ok(())
}

fn short_id(id: &str) -> String {
    match agentsc_common::identity::SpiffeId::parse(id) {
        Some(s) => format!("svc/{}", s.service),
        None => id.to_string(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}
