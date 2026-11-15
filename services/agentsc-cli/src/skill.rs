//! `agentsc skill import` and `agentsc skill export`: move skills between Agent Skills
//! directories (a `SKILL.md` each, <https://agentskills.io/specification>) and a charter's
//! top-level `skills` (CONTRACT.md §3.3). A charter skill is instructions only, and attache has
//! no sandbox: a skill that ships `scripts/` or `assets/` is refused, and `references/` becomes
//! part of the instructions only when asked. The frontmatter the charter has no field for
//! (`allowed-tools`, `license`, `compatibility`, `metadata`) becomes comment lines for a person to
//! read, never charter fields.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};

use agentsc_charter::{
    Charter, MAX_SKILL_DESCRIPTION_CHARS, MAX_SKILL_INSTRUCTIONS_BYTES, MAX_SKILLS, SkillSpec,
    is_dns_label,
};
use agentsc_common::audit::sha256_hex;
use anyhow::{Context, anyhow, bail};
use serde::Serialize;
use serde_yaml_ng::Value;

/// The file that makes a directory a skill.
const SKILL_FILE: &str = "SKILL.md";
/// The longest `name` the Agent Skills spec allows (a charter skill name is at most 63).
const MAX_NAME_CHARS: usize = 64;
/// The longest `compatibility` the Agent Skills spec allows.
const MAX_COMPATIBILITY_CHARS: usize = 500;
/// The most of a `SKILL.md` read: far more than a charter skill can hold.
const MAX_SKILL_FILE_BYTES: u64 = 1024 * 1024;
/// How deep `--inline-references` walks into directories under `references/`.
const MAX_REFERENCE_DEPTH: usize = 8;
/// At most this many entries are named in the "not imported" comment.
const MAX_LISTED: usize = 10;
/// `metadata.source` of an exported skill.
const EXPORT_SOURCE: &str = "attache charter";

#[derive(clap::Subcommand)]
pub enum SkillCmd {
    /// Print entries for the charter's top-level `skills:` from Agent Skills directories (each
    /// holding a SKILL.md), each after a comment naming its directory and the SKILL.md's sha256.
    Import(ImportArgs),
    /// Write `<out>/<name>/SKILL.md` in the Agent Skills format for a charter's skills.
    Export(ExportArgs),
}

#[derive(clap::Args)]
pub struct ImportArgs {
    /// Skill directories; each holds a SKILL.md and is named as its skill.
    #[arg(required = true)]
    dirs: Vec<PathBuf>,
    /// Append the text files under `references/` to the instructions, a `## references/<file>`
    /// section each. Without it, a skill with references is refused.
    #[arg(long)]
    inline_references: bool,
}

#[derive(clap::Args)]
pub struct ExportArgs {
    /// The charter (plain or custom resource form).
    charter: PathBuf,
    /// The directory to write the skill directories in.
    #[arg(long)]
    out: PathBuf,
    /// A skill to export, by name; repeat for more (default: every skill of the charter).
    #[arg(long = "skill", value_name = "NAME")]
    skills: Vec<String>,
    /// Overwrite an existing SKILL.md.
    #[arg(long)]
    force: bool,
}

pub fn run(cmd: SkillCmd) -> anyhow::Result<i32> {
    match cmd {
        SkillCmd::Import(a) => {
            print!("{}", import(&a.dirs, a.inline_references)?);
            Ok(0)
        }
        SkillCmd::Export(a) => export(&a).map(|()| 0),
    }
}

/// One imported skill: the comment lines that go before it, and the entry.
struct Imported {
    comments: Vec<String>,
    skill: SkillSpec,
}

/// The YAML of the import: per skill, its comment lines and one list item.
fn import(dirs: &[PathBuf], inline_references: bool) -> anyhow::Result<String> {
    if dirs.len() > MAX_SKILLS {
        bail!(
            "a charter holds at most {MAX_SKILLS} skills, got {} directories",
            dirs.len()
        );
    }
    let mut out = String::new();
    let mut seen: BTreeMap<String, &Path> = BTreeMap::new();
    for dir in dirs {
        let Imported { comments, skill } = import_dir(dir, inline_references)?;
        if let Some(first) = seen.insert(skill.name.clone(), dir) {
            bail!(
                "{}: skill {:?} is also imported from {}; skill names are unique in a charter",
                dir.display(),
                skill.name,
                first.display()
            );
        }
        for line in comments {
            out.push_str("# ");
            out.push_str(&one_line(&line));
            out.push('\n');
        }
        out.push_str(&serde_yaml_ng::to_string(&[&skill])?);
    }
    Ok(out)
}

/// One skill directory as a charter skill, or why it cannot be one.
fn import_dir(dir: &Path, inline_references: bool) -> anyhow::Result<Imported> {
    // Only the directory named on the command line may be a symlink: nothing inside it is followed.
    let root = std::fs::canonicalize(dir).with_context(|| format!("reading {}", dir.display()))?;
    if !root.is_dir() {
        bail!(
            "{}: not a directory (a skill is a directory holding {SKILL_FILE})",
            dir.display()
        );
    }
    let file = dir.join(SKILL_FILE);
    let bytes = read_regular(&root.join(SKILL_FILE), &file, MAX_SKILL_FILE_BYTES)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| anyhow!("{}: not UTF-8 text", file.display()))?;
    let at = |rule: String| anyhow!("{}: {rule}", file.display());
    let (yaml, body) = split_frontmatter(text).map_err(at)?;
    let fm = parse_frontmatter(yaml).map_err(at)?;
    check_name(&fm.name).map_err(at)?;
    let dir_name = root.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if fm.name != dir_name {
        return Err(at(format!(
            "name {:?} does not match its directory name {dir_name:?} (the Agent Skills spec requires them equal)",
            fm.name
        )));
    }
    check_description(&fm.description).map_err(at)?;
    if let Some(c) = &fm.compatibility {
        let n = c.chars().count();
        if c.trim().is_empty() || n > MAX_COMPATIBILITY_CHARS {
            return Err(at(format!(
                "compatibility must be 1 to {MAX_COMPATIBILITY_CHARS} characters, got {n}"
            )));
        }
    }
    let mut instructions = body.trim().to_string();
    if instructions.is_empty() {
        return Err(at(
            "the Markdown body is empty; it becomes the skill's instructions, which may not be empty"
                .into(),
        ));
    }

    if non_empty(&root.join("scripts"), &dir.join("scripts"))? {
        bail!(
            "{}: scripts/ is not empty: attache cannot run skill scripts; there is no sandbox",
            dir.display()
        );
    }
    if non_empty(&root.join("assets"), &dir.join("assets"))? {
        bail!(
            "{}: assets/ is not empty: a charter skill is instructions only, and attache cannot give an agent the skill's files",
            dir.display()
        );
    }
    let mut comments = vec![format!(
        "Agent Skill {} ({SKILL_FILE} sha256:{}), imported by agentsc skill import.",
        dir.display(),
        sha256_hex(&bytes)
    )];
    let shown_refs = dir.join("references");
    if non_empty(&root.join("references"), &shown_refs)? {
        if !inline_references {
            bail!(
                "{}: references/ is not empty: pass --inline-references to append its text files to the instructions",
                dir.display()
            );
        }
        for (rel, text) in read_references(&root.join("references"), &shown_refs)? {
            comments.push(format!(
                "references/{rel} sha256:{} (inlined)",
                sha256_hex(text.as_bytes())
            ));
            let text = text.trim_start_matches(['\n', '\r']).trim_end();
            write!(instructions, "\n\n## references/{rel}\n\n{text}")?;
        }
        if instructions.len() > MAX_SKILL_INSTRUCTIONS_BYTES {
            bail!(
                "{}: the instructions with references/ inlined are {} bytes; a charter skill's instructions are at most {MAX_SKILL_INSTRUCTIONS_BYTES} bytes",
                dir.display(),
                instructions.len()
            );
        }
    }
    if instructions.len() > MAX_SKILL_INSTRUCTIONS_BYTES {
        return Err(at(format!(
            "the Markdown body is {} bytes; a charter skill's instructions are at most {MAX_SKILL_INSTRUCTIONS_BYTES} bytes",
            instructions.len()
        )));
    }

    if let Some(v) = &fm.license {
        comments.push(format!("license: {v}"));
    }
    if let Some(v) = &fm.compatibility {
        comments.push(format!("compatibility: {v}"));
    }
    for (k, v) in &fm.metadata {
        comments.push(format!("metadata {k}: {v}"));
    }
    if !fm.unknown.is_empty() {
        comments.push(format!(
            "ignored frontmatter fields the Agent Skills spec does not define: {}",
            fm.unknown.join(", ")
        ));
    }
    let others = other_entries(&root)?;
    if !others.is_empty() {
        comments.push(format!(
            "not imported: {others} (a charter skill holds the {SKILL_FILE} instructions only)"
        ));
    }
    if let Some(v) = &fm.allowed_tools {
        comments.push(format!(
            "allowed-tools: {v} (tool names of the skill's host agent, not charter tools)"
        ));
    }
    comments.push(
        "tools: none imported. List the charter tools these instructions use under `tools`; each must be allowed for every agent that uses the skill."
            .into(),
    );
    Ok(Imported {
        comments,
        skill: SkillSpec {
            name: fm.name,
            description: fm.description,
            instructions,
            tools: Vec::new(),
        },
    })
}

/// `s` on one line, for a comment: a line break in a value read from a skill must not end the
/// comment and put YAML of the skill's choosing into the charter.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// A regular file's bytes (never through a symlink), at most `max`; `shown` names it in errors.
fn read_regular(path: &Path, shown: &Path, max: u64) -> anyhow::Result<Vec<u8>> {
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("reading {}", shown.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "{}: a symlink; attache follows no symlinks in a skill directory",
            shown.display()
        );
    }
    if !meta.is_file() {
        bail!("{}: not a regular file", shown.display());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(max + 1).read_to_end(&mut bytes))
        .with_context(|| format!("reading {}", shown.display()))?;
    if bytes.len() as u64 > max {
        bail!("{}: more than {max} bytes", shown.display());
    }
    Ok(bytes)
}

/// Whether `path` (`shown` in errors) has anything in it: absent or an empty directory is
/// nothing, a file of that name is something, and a symlink is refused.
fn non_empty(path: &Path, shown: &Path) -> anyhow::Result<bool> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("reading {}", shown.display())),
    };
    if meta.file_type().is_symlink() {
        bail!(
            "{}: a symlink; attache follows no symlinks in a skill directory",
            shown.display()
        );
    }
    if !meta.is_dir() {
        return Ok(true);
    }
    let mut entries =
        std::fs::read_dir(path).with_context(|| format!("reading {}", shown.display()))?;
    Ok(entries.next().is_some())
}

/// The entries of a skill directory besides SKILL.md, scripts, references and assets, for the
/// "not imported" comment.
fn other_entries(root: &Path) -> anyhow::Result<String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if [SKILL_FILE, "scripts", "references", "assets"].contains(&name.as_str()) {
            continue;
        }
        let dir = entry.file_type().is_ok_and(|t| t.is_dir());
        names.push(if dir { format!("{name}/") } else { name });
    }
    names.sort();
    let more = names.len().saturating_sub(MAX_LISTED);
    names.truncate(MAX_LISTED);
    let mut text = names.join(", ");
    if more > 0 {
        write!(text, " and {more} more")?;
    }
    Ok(text)
}

/// The files under `references/` (`dir`, `shown` in errors) as `(path below references/, text)`,
/// sorted by path. Only regular UTF-8 text files in real directories: a symlink, a binary file or
/// anything else is refused, so nothing outside the skill directory is ever read.
fn read_references(dir: &Path, shown: &Path) -> anyhow::Result<Vec<(String, String)>> {
    fn walk(
        dir: &Path,
        shown: &Path,
        prefix: &str,
        depth: usize,
        out: &mut Vec<(String, String)>,
    ) -> anyhow::Result<()> {
        if depth > MAX_REFERENCE_DEPTH {
            bail!(
                "{}: more than {MAX_REFERENCE_DEPTH} directories deep under references/",
                shown.display()
            );
        }
        for entry in
            std::fs::read_dir(dir).with_context(|| format!("reading {}", shown.display()))?
        {
            let entry = entry?;
            let file_name = entry.file_name();
            let shown = shown.join(&file_name);
            let Some(name) = file_name
                .to_str()
                .filter(|n| !n.chars().any(char::is_control))
            else {
                bail!("{}: the file name is not printable UTF-8", shown.display());
            };
            let rel = format!("{prefix}{name}");
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .with_context(|| format!("reading {}", shown.display()))?;
            if meta.is_dir() {
                walk(&path, &shown, &format!("{rel}/"), depth + 1, out)?;
                continue;
            }
            let bytes = read_regular(&path, &shown, MAX_SKILL_INSTRUCTIONS_BYTES as u64)?;
            if bytes.contains(&0) {
                bail!(
                    "{}: a binary file; only text references can be inlined",
                    shown.display()
                );
            }
            let text = String::from_utf8(bytes).map_err(|_| {
                anyhow!(
                    "{}: not UTF-8 text; only text references can be inlined",
                    shown.display()
                )
            })?;
            out.push((rel, text));
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, shown, "", 0, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The YAML frontmatter and the Markdown body of a SKILL.md.
fn split_frontmatter(text: &str) -> Result<(&str, &str), String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.split_inclusive('\n');
    let first = lines.next().unwrap_or("");
    if first.trim_end() != "---" {
        return Err("does not start with a `---` line (the YAML frontmatter is required)".into());
    }
    let start = first.len();
    let mut end = start;
    for line in lines {
        if line.trim_end() == "---" {
            return Ok((&text[start..end], &text[end + line.len()..]));
        }
        end += line.len();
    }
    Err("the YAML frontmatter has no closing `---` line".into())
}

/// The frontmatter fields of a SKILL.md (Agent Skills spec).
#[derive(Debug, Default, PartialEq)]
struct Frontmatter {
    name: String,
    description: String,
    license: Option<String>,
    compatibility: Option<String>,
    /// In the order written.
    metadata: Vec<(String, String)>,
    allowed_tools: Option<String>,
    /// Keys the spec does not define; ignored.
    unknown: Vec<String>,
}

/// The frontmatter's fields, each of the type the spec gives it.
fn parse_frontmatter(yaml: &str) -> Result<Frontmatter, String> {
    fn string(key: &str, v: Value) -> Result<String, String> {
        match v {
            Value::String(s) => Ok(s),
            _ => Err(format!("`{key}` must be a string")),
        }
    }
    let doc: Value = serde_yaml_ng::from_str(yaml)
        .map_err(|e| format!("the frontmatter is not valid YAML ({e})"))?;
    let map = match doc {
        Value::Mapping(m) => m,
        Value::Null => serde_yaml_ng::Mapping::new(),
        _ => return Err("the frontmatter is not a YAML mapping".into()),
    };
    let mut fm = Frontmatter::default();
    let (mut name, mut description) = (None, None);
    for (k, v) in map {
        let Value::String(key) = k else {
            return Err(format!("the frontmatter key {k:?} is not a string"));
        };
        match key.as_str() {
            "name" => name = Some(string(&key, v)?),
            "description" => description = Some(string(&key, v)?),
            "license" => fm.license = Some(string(&key, v)?),
            "compatibility" => fm.compatibility = Some(string(&key, v)?),
            "allowed-tools" => fm.allowed_tools = Some(string(&key, v)?),
            "metadata" => {
                let entries = match v {
                    Value::Mapping(m) => m,
                    Value::Null => continue,
                    _ => return Err("`metadata` must be a map from strings to strings".into()),
                };
                for (mk, mv) in entries {
                    let Value::String(mk) = mk else {
                        return Err(format!("`metadata` key {mk:?} is not a string"));
                    };
                    let Value::String(mv) = mv else {
                        return Err(format!(
                            "`metadata.{mk}` must be a string (metadata maps strings to strings: quote values such as \"1.0\")"
                        ));
                    };
                    fm.metadata.push((mk, mv));
                }
            }
            _ => fm.unknown.push(key),
        }
    }
    fm.name = name.ok_or("`name` is required")?;
    fm.description = description.ok_or("`description` is required")?;
    Ok(fm)
}

/// The Agent Skills `name` rules, and a charter skill's (a DNS-1123 label).
fn check_name(name: &str) -> Result<(), String> {
    let n = name.chars().count();
    if n == 0 || n > MAX_NAME_CHARS {
        return Err(format!(
            "name {name:?} must be 1 to {MAX_NAME_CHARS} characters, got {n}"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "name {name:?} may contain only lowercase letters a-z, digits 0-9 and hyphens"
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(format!("name {name:?} must not start or end with a hyphen"));
    }
    if name.contains("--") {
        return Err(format!(
            "name {name:?} must not contain consecutive hyphens"
        ));
    }
    if !is_dns_label(name) {
        return Err(format!(
            "name {name:?} is not a DNS-1123 label (at most 63 characters), which a charter skill name must be"
        ));
    }
    Ok(())
}

/// `description`: 1 to 1024 characters, not blank (the spec's rule and the charter's).
fn check_description(description: &str) -> Result<(), String> {
    let n = description.chars().count();
    if description.trim().is_empty() || n > MAX_SKILL_DESCRIPTION_CHARS {
        return Err(format!(
            "description must be 1 to {MAX_SKILL_DESCRIPTION_CHARS} characters, got {n}"
        ));
    }
    Ok(())
}

/// The frontmatter of an exported skill.
#[derive(Serialize)]
struct ExportFrontmatter<'a> {
    name: &'a str,
    description: &'a str,
    metadata: ExportMetadata,
}

#[derive(Serialize)]
struct ExportMetadata {
    source: &'static str,
    #[serde(rename = "charter-tools", skip_serializing_if = "Option::is_none")]
    charter_tools: Option<String>,
}

/// The SKILL.md of a charter skill: `name`, `description`, `metadata` (`source`, and the charter
/// tools the instructions use as `charter-tools`), and the instructions as the body.
fn skill_md(skill: &SkillSpec) -> anyhow::Result<String> {
    check_name(&skill.name)
        .map_err(|e| anyhow!("skill {:?}: {e} (Agent Skills spec)", skill.name))?;
    let frontmatter = ExportFrontmatter {
        name: &skill.name,
        description: &skill.description,
        metadata: ExportMetadata {
            source: EXPORT_SOURCE,
            charter_tools: (!skill.tools.is_empty()).then(|| skill.tools.join(" ")),
        },
    };
    let yaml = serde_yaml_ng::to_string(&frontmatter)?;
    Ok(format!("---\n{yaml}---\n\n{}\n", skill.instructions.trim()))
}

/// Writes the SKILL.md files, one line per file; every check runs before the first write.
fn export(a: &ExportArgs) -> anyhow::Result<()> {
    let charter = Charter::load(&a.charter).map_err(|e| {
        anyhow!(
            "{}: {}",
            a.charter.display(),
            agentsc_common::error::chain(&e)
        )
    })?;
    let mut selected: Vec<&SkillSpec> = Vec::new();
    if a.skills.is_empty() {
        selected.extend(&charter.skills);
    } else {
        for name in &a.skills {
            let skill = charter
                .skill(name)
                .with_context(|| format!("{}: no skill {name:?}", a.charter.display()))?;
            if !selected.iter().any(|s| s.name == skill.name) {
                selected.push(skill);
            }
        }
    }
    if selected.is_empty() {
        println!("{}: no skills", a.charter.display());
        return Ok(());
    }
    let mut plan = Vec::new();
    for skill in selected {
        let content = skill_md(skill)?;
        let dir = a.out.join(&skill.name);
        let file = dir.join(SKILL_FILE);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_symlink() => {
                bail!("{}: a symlink; refusing to write through it", dir.display())
            }
            Ok(m) if !m.is_dir() => bail!("{}: exists and is not a directory", dir.display()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        }
        match std::fs::symlink_metadata(&file) {
            Ok(m) if m.file_type().is_symlink() => {
                bail!(
                    "{}: a symlink; refusing to write through it",
                    file.display()
                )
            }
            Ok(m) if !m.is_file() => bail!("{}: exists and is not a file", file.display()),
            Ok(_) if !a.force => bail!("{}: exists; pass --force to overwrite it", file.display()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
        }
        plan.push((dir, file, content));
    }
    for (dir, file, content) in plan {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::write(&file, content).with_context(|| format!("writing {}", file.display()))?;
        println!("wrote {}", file.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MD: &str = "---\nname: pdf-tools\ndescription: Extract text from PDFs. Use when a PDF is attached.\n---\n\n# PDF\n\nRead the PDF page by page.\n";

    /// `root/<name>/SKILL.md` with `md`; the skill directory.
    fn skill_dir(root: &Path, name: &str, md: &str) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SKILL_FILE), md).unwrap();
        dir
    }

    fn err(r: anyhow::Result<Imported>) -> String {
        match r {
            Ok(i) => panic!("imported {:?}", i.skill),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn frontmatter_is_split_and_typed() {
        let (yaml, body) = split_frontmatter("\u{feff}---\r\nname: a\r\n---\r\nbody\n").unwrap();
        assert_eq!(yaml, "name: a\r\n");
        assert_eq!(body, "body\n");
        assert!(
            split_frontmatter("name: a\n")
                .unwrap_err()
                .contains("`---`")
        );
        assert!(
            split_frontmatter("---\nname: a\n")
                .unwrap_err()
                .contains("no closing")
        );

        let fm = parse_frontmatter(
            "name: a\ndescription: d\nlicense: MIT\ncompatibility: Requires git\nallowed-tools: Bash(git:*) Read\nmetadata:\n  author: me\n  version: \"1.0\"\nuser-invocable: true\n",
        )
        .unwrap();
        assert_eq!(fm.name, "a");
        assert_eq!(fm.license.as_deref(), Some("MIT"));
        assert_eq!(fm.allowed_tools.as_deref(), Some("Bash(git:*) Read"));
        assert_eq!(
            fm.metadata,
            vec![
                ("author".into(), "me".into()),
                ("version".into(), "1.0".into())
            ]
        );
        assert_eq!(fm.unknown, vec!["user-invocable".to_string()]);

        let e = parse_frontmatter("name: a\ndescription: d\nmetadata:\n  version: 1.0\n");
        assert!(
            e.unwrap_err()
                .contains("`metadata.version` must be a string")
        );
        assert!(
            parse_frontmatter("name: 7\ndescription: d\n")
                .unwrap_err()
                .contains("`name` must be a string")
        );
        assert!(
            parse_frontmatter("name: a\n")
                .unwrap_err()
                .contains("`description` is required")
        );
        assert!(parse_frontmatter("- a\n").unwrap_err().contains("mapping"));
    }

    #[test]
    fn name_rules() {
        let longest = "a".repeat(63);
        for ok in ["pdf-processing", "a", "a1-b2", longest.as_str()] {
            check_name(ok).unwrap();
        }
        let rule = |n: &str| check_name(n).unwrap_err();
        assert!(rule("PDF-Processing").contains("lowercase"));
        assert!(rule("pdf_tools").contains("lowercase"));
        assert!(rule("-pdf").contains("start or end"));
        assert!(rule("pdf-").contains("start or end"));
        assert!(rule("pdf--processing").contains("consecutive"));
        assert!(rule("").contains("1 to 64"));
        assert!(rule(&"a".repeat(65)).contains("1 to 64"));
        // the spec allows 64 characters; a charter skill name is a DNS label (63)
        assert!(rule(&"a".repeat(64)).contains("DNS-1123"));
    }

    #[test]
    fn imports_a_skill_and_checks_it_against_its_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = skill_dir(tmp.path(), "pdf-tools", MD);
        std::fs::create_dir(dir.join("scripts")).unwrap(); // empty: fine
        std::fs::write(dir.join("LICENSE.txt"), "MIT").unwrap();
        let i = import_dir(&dir, false).unwrap();
        assert_eq!(i.skill.name, "pdf-tools");
        assert_eq!(
            i.skill.description,
            "Extract text from PDFs. Use when a PDF is attached."
        );
        assert_eq!(i.skill.instructions, "# PDF\n\nRead the PDF page by page.");
        assert!(i.skill.tools.is_empty());
        let sha = sha256_hex(MD.as_bytes());
        assert!(
            i.comments[0].contains(&format!("SKILL.md sha256:{sha}")),
            "{:?}",
            i.comments
        );
        assert!(
            i.comments
                .iter()
                .any(|c| c.starts_with("not imported: LICENSE.txt")),
            "{:?}",
            i.comments
        );

        let other = skill_dir(tmp.path(), "other", MD);
        assert!(err(import_dir(&other, false)).contains("does not match its directory name"));
        let empty = skill_dir(
            tmp.path(),
            "empty",
            "---\nname: empty\ndescription: d\n---\n \n",
        );
        assert!(err(import_dir(&empty, false)).contains("body is empty"));
        let long = "a".repeat(MAX_SKILL_DESCRIPTION_CHARS + 1);
        let desc = skill_dir(
            tmp.path(),
            "desc",
            &format!("---\nname: desc\ndescription: {long}\n---\nx\n"),
        );
        let e = err(import_dir(&desc, false));
        assert!(e.contains("SKILL.md: description must be 1 to 1024"), "{e}");
        let compat = skill_dir(
            tmp.path(),
            "compat",
            &format!(
                "---\nname: compat\ndescription: d\ncompatibility: {}\n---\nx\n",
                "c".repeat(501)
            ),
        );
        assert!(err(import_dir(&compat, false)).contains("compatibility must be 1 to 500"));
    }

    #[test]
    fn refuses_scripts_and_assets() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = skill_dir(tmp.path(), "pdf-tools", MD);
        std::fs::create_dir(dir.join("scripts")).unwrap();
        std::fs::write(dir.join("scripts/extract.py"), "print(1)").unwrap();
        let e = err(import_dir(&dir, true));
        assert!(e.contains("scripts/ is not empty"), "{e}");
        assert!(e.contains("no sandbox"), "{e}");
        std::fs::remove_dir_all(dir.join("scripts")).unwrap();
        std::fs::create_dir(dir.join("assets")).unwrap();
        std::fs::write(dir.join("assets/template.docx"), "x").unwrap();
        assert!(err(import_dir(&dir, true)).contains("assets/ is not empty"));
    }

    #[test]
    fn inlines_references_only_when_asked() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = skill_dir(tmp.path(), "pdf-tools", MD);
        std::fs::create_dir_all(dir.join("references/forms")).unwrap();
        std::fs::write(dir.join("references/REFERENCE.md"), "\nAll the API.\n\n").unwrap();
        std::fs::write(dir.join("references/forms/w9.md"), "Fill line 1.").unwrap();
        let e = err(import_dir(&dir, false));
        assert!(e.contains("--inline-references"), "{e}");
        let i = import_dir(&dir, true).unwrap();
        assert_eq!(
            i.skill.instructions,
            "# PDF\n\nRead the PDF page by page.\n\n## references/REFERENCE.md\n\nAll the API.\n\n## references/forms/w9.md\n\nFill line 1."
        );
        assert!(
            i.comments
                .iter()
                .any(|c| c.starts_with("references/forms/w9.md sha256:")),
            "{:?}",
            i.comments
        );

        std::fs::write(dir.join("references/logo.png"), [0x89, b'P', 0, 1]).unwrap();
        assert!(err(import_dir(&dir, true)).contains("logo.png: a binary file"));
        std::fs::write(dir.join("references/logo.png"), [0xff, 0xfe]).unwrap();
        assert!(err(import_dir(&dir, true)).contains("logo.png: not UTF-8 text"));
        std::fs::remove_file(dir.join("references/logo.png")).unwrap();

        #[cfg(unix)]
        {
            std::fs::write(tmp.path().join("secret.txt"), "outside").unwrap();
            std::os::unix::fs::symlink(
                tmp.path().join("secret.txt"),
                dir.join("references/secret.md"),
            )
            .unwrap();
            assert!(err(import_dir(&dir, true)).contains("secret.md: a symlink"));
            std::fs::remove_file(dir.join("references/secret.md")).unwrap();
            std::os::unix::fs::symlink(tmp.path(), dir.join("references/up")).unwrap();
            assert!(err(import_dir(&dir, true)).contains("up: a symlink"));
            std::fs::remove_file(dir.join("references/up")).unwrap();
        }
        import_dir(&dir, true).unwrap();
    }

    #[test]
    fn instructions_must_fit_the_charter() {
        let tmp = tempfile::tempdir().unwrap();
        let big = "x".repeat(MAX_SKILL_INSTRUCTIONS_BYTES + 1);
        let dir = skill_dir(
            tmp.path(),
            "big",
            &format!("---\nname: big\ndescription: d\n---\n{big}\n"),
        );
        assert!(err(import_dir(&dir, false)).contains("at most 32768 bytes"));

        // a body that fits, and references that make it too big together
        let dir = skill_dir(
            tmp.path(),
            "near",
            &format!(
                "---\nname: near\ndescription: d\n---\n{}\n",
                "x".repeat(MAX_SKILL_INSTRUCTIONS_BYTES - 10)
            ),
        );
        std::fs::create_dir(dir.join("references")).unwrap();
        std::fs::write(dir.join("references/a.md"), "more text").unwrap();
        let e = err(import_dir(&dir, true));
        assert!(e.contains("with references/ inlined"), "{e}");
    }

    #[test]
    fn untrusted_values_stay_in_their_comment() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = skill_dir(
            tmp.path(),
            "pdf-tools",
            "---\nname: pdf-tools\ndescription: d\nlicense: \"MIT\\n- name: evil\\n  description: e\\n  instructions: i\"\nallowed-tools: \"Read\\u2028- x\"\n---\nbody\u{2028}- name: other\u{85}x: y\n",
        );
        let yaml = import(&[dir], false).unwrap();
        let skills: Vec<SkillSpec> = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(skills.len(), 1, "{yaml}");
        assert_eq!(
            skills[0].instructions,
            "body\u{2028}- name: other\u{85}x: y"
        );
        assert!(yaml.contains("# license: MIT - name: evil "), "{yaml}");
        assert!(
            yaml.contains("# allowed-tools: Read - x (tool names"),
            "{yaml}"
        );
        assert!(
            yaml.lines()
                .all(|l| l.starts_with("# ") || !l.contains("evil")),
            "{yaml}"
        );
    }

    #[test]
    fn import_refuses_the_same_name_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = skill_dir(tmp.path(), "pdf-tools", MD);
        let e = import(&[dir.clone(), dir], false).unwrap_err().to_string();
        assert!(e.contains("also imported"), "{e}");
    }

    #[test]
    fn export_writes_the_frontmatter_and_round_trips() {
        let skill = SkillSpec {
            name: "refund-policy".into(),
            description: "Refund rules: when to refund. Use for refunds.".into(),
            instructions: "Refund under 50 EUR.\n\n- ask above that\n".into(),
            tools: vec!["get_order".into(), "issue_refund".into()],
        };
        let md = skill_md(&skill).unwrap();
        assert!(md.starts_with("---\nname: refund-policy\n"), "{md}");
        let (yaml, body) = split_frontmatter(&md).unwrap();
        let fm = parse_frontmatter(yaml).unwrap();
        assert_eq!(fm.description, skill.description);
        assert_eq!(
            fm.metadata,
            vec![
                ("source".into(), EXPORT_SOURCE.into()),
                ("charter-tools".into(), "get_order issue_refund".into())
            ]
        );
        assert_eq!(body.trim(), skill.instructions.trim());

        let no_tools = SkillSpec {
            tools: Vec::new(),
            ..skill.clone()
        };
        assert!(!skill_md(&no_tools).unwrap().contains("charter-tools"));
        // a DNS label the Agent Skills spec does not allow
        let bad = SkillSpec {
            name: "refund--policy".into(),
            ..skill
        };
        assert!(
            skill_md(&bad)
                .unwrap_err()
                .to_string()
                .contains("consecutive")
        );
    }
}
