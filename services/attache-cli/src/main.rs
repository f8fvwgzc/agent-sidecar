//! `attache` — the CLI (CONTRACT.md §8).
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use attache_charter::Charter;
use attache_common::audit::AuditRecord;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "attache",
    version,
    about = "attache: governed AI agents as a sidecar of your service"
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
    /// Validate a charter; exit 1 with one error per line when invalid.
    Validate { file: std::path::PathBuf },
    /// Print the JSON Schema for charter.yaml.
    Schema,
}

#[derive(clap::Args)]
struct LogsArgs {
    /// Service name(s), comma-separated (label attache.io/service). Ignored with --file.
    #[arg(default_value = "")]
    service: String,
    #[arg(short = 'n', long, default_value = "attache-demo")]
    namespace: String,
    /// Only records of this agent.
    #[arg(long)]
    agent: Option<String>,
    /// Only records of this trace id.
    #[arg(long)]
    trace: Option<String>,
    /// Only records of this request id.
    #[arg(long)]
    request: Option<String>,
    /// Only records of this kind (agent_invocation, model_call, tool_call, agent_call, service_call, http_call, authz, guardrail, budget).
    #[arg(long)]
    kind: Option<String>,
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
            cmd: CharterCmd::Schema,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&attache_charter::json_schema()).unwrap()
            );
            0
        }
        Cmd::Logs(args) => match logs(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        },
        Cmd::Version => {
            println!("attache {}", env!("CARGO_PKG_VERSION"));
            0
        }
    };
    std::process::exit(code);
}

fn logs(args: LogsArgs) -> anyhow::Result<()> {
    let reader: Box<dyn BufRead> = match &args.file {
        Some(f) if f == "-" => Box::new(BufReader::new(std::io::stdin())),
        Some(f) => Box::new(BufReader::new(std::fs::File::open(f)?)),
        None => {
            if args.service.is_empty() {
                anyhow::bail!("usage: attache logs <service> [--agent A] [--trace T] [-f]");
            }
            let mut cmd = Command::new("kubectl");
            let selector = if args.service.contains(',') {
                format!("attache.io/service in ({})", args.service)
            } else {
                format!("attache.io/service={}", args.service)
            };
            cmd.args([
                "logs",
                "-n",
                &args.namespace,
                "-l",
                &selector,
                "-c",
                "attached",
                "--tail",
                &args.tail.to_string(),
                "--prefix=false",
            ]);
            if args.follow {
                cmd.arg("-f");
            }
            let child = cmd
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| anyhow::anyhow!("cannot run kubectl: {e}"))?;
            Box::new(BufReader::new(child.stdout.unwrap()))
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut records: Vec<AuditRecord> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim_start();
        let json_start = match trimmed.find('{') {
            Some(i) => i,
            None => continue,
        };
        let Ok(rec) = serde_json::from_str::<AuditRecord>(&trimmed[json_start..]) else {
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
            && serde_json::to_value(rec.kind)?.as_str() != Some(k.as_str())
        {
            continue;
        }
        if args.denied && rec.decision != "deny" {
            continue;
        }
        if args.follow {
            print_record(&mut out, &rec, args.raw)?;
        } else {
            records.push(rec);
        }
    }
    // Without --follow, kubectl returns one pod's log after another: sort by time so a trace reads top to bottom.
    records.sort_by(|a, b| a.ts.cmp(&b.ts));
    for rec in &records {
        print_record(&mut out, rec, args.raw)?;
    }
    Ok(())
}

fn print_record(out: &mut impl Write, rec: &AuditRecord, raw: bool) -> anyhow::Result<()> {
    if raw {
        writeln!(out, "{}", rec.to_json_line())?;
        return Ok(());
    }
    let ts = rec.ts.get(11..23).unwrap_or(&rec.ts);
    let kind = serde_json::to_value(rec.kind)?
        .as_str()
        .unwrap_or("?")
        .to_string();
    let dir = serde_json::to_value(rec.direction)?
        .as_str()
        .unwrap_or("?")
        .to_string();
    let caller = short_id(&rec.caller);
    let caller = match &rec.caller_agent {
        Some(a)
            if rec.kind != attache_common::audit::Kind::AgentInvocation
                || rec.caller != "local" =>
        {
            format!("{caller} ({a})")
        }
        _ => caller,
    };
    let decision = if rec.decision == "deny" {
        format!("DENY {}", rec.rule.clone().unwrap_or_default())
    } else {
        match &rec.rule {
            Some(r) if r.starts_with("guardrail.pii") => format!("allow {r}"),
            _ => "allow".to_string(),
        }
    };
    let extra = match (&rec.tokens, rec.cost_usd) {
        (Some(t), Some(c)) if t.input + t.output > 0 => {
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
        &rec.trace_id[..rec.trace_id.len().min(8)],
    )?;
    Ok(())
}

fn short_id(id: &str) -> String {
    match attache_common::identity::SpiffeId::parse(id) {
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
