//! The platform's LLM connection contract v1 (docs/LLM-CONNECTION.md): the `LLM_*` environment
//! variables every core reads (texc-symphony, onto-intelli, attache), so one Kubernetes Secret and
//! ConfigMap configure model access everywhere.
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `LLM_PROVIDER` | `anthropic`, `openai` or `openai-compatible`; in gateway mode the wire format |
//! | `LLM_BASE_URL` | the provider's API base URL (required for `openai-compatible`) |
//! | `LLM_API_KEY_FILE` | file holding the key, re-read for every request; wins over `LLM_API_KEY` |
//! | `LLM_API_KEY` | the key as text |
//! | `LLM_MODEL` | the model (required) |
//! | `LLM_MODEL_SMALL` | a small, fast model |
//! | `LLM_TIMEOUT_SECS` | timeout of one model request (`> 0`) |
//! | `LLM_MAX_RETRIES` | retries of one request (`0..=10`) |
//! | `LLM_GATEWAY_URL` | gateway mode: every call goes to the platform's model gateway (a trailing `/v1` is ignored) |
//! | `LLM_GATEWAY_TOKEN_FILE` | the gateway token, sent as a bearer token (required with the gateway) |
//!
//! The contract applies once `LLM_PROVIDER` or `LLM_GATEWAY_URL` is set. Other `LLM_*` without
//! one of them are ignored with a warning (`Ignoring LLM_MODEL without LLM_PROVIDER or
//! LLM_GATEWAY_URL`). An invalid value of an active contract is an error that names the variable
//! (`LLM_MODEL can't be blank`, `LLM_PROVIDER is invalid`), never the key. An empty value counts
//! as unset.
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Every variable of the contract.
pub const VARIABLES: [&str; 10] = [
    "LLM_PROVIDER",
    "LLM_BASE_URL",
    "LLM_API_KEY_FILE",
    "LLM_API_KEY",
    "LLM_MODEL",
    "LLM_MODEL_SMALL",
    "LLM_TIMEOUT_SECS",
    "LLM_MAX_RETRIES",
    "LLM_GATEWAY_URL",
    "LLM_GATEWAY_TOKEN_FILE",
];
/// The variables that hold or name a secret: a process that starts a less trusted one removes
/// them from its environment.
pub const SECRET_VARIABLES: [&str; 3] =
    ["LLM_API_KEY", "LLM_API_KEY_FILE", "LLM_GATEWAY_TOKEN_FILE"];
pub const ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";
pub const OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
/// The most retries `LLM_MAX_RETRIES` may ask for.
pub const MAX_RETRIES: u32 = 10;

/// `LLM_PROVIDER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// The Anthropic Messages API.
    Anthropic,
    /// OpenAI (Chat Completions and Responses).
    OpenAi,
    /// Anything that speaks OpenAI Chat Completions at `LLM_BASE_URL` (Ollama, vLLM, LM Studio,
    /// OpenRouter, Groq, Together, Gemini's OpenAI endpoint, Azure OpenAI).
    OpenAiCompatible,
}

impl ProviderKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "anthropic" => Some(Self::Anthropic),
            "openai" => Some(Self::OpenAi),
            "openai-compatible" => Some(Self::OpenAiCompatible),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::OpenAiCompatible => "openai-compatible",
        }
    }

    /// The base URL when `LLM_BASE_URL` is not set (`openai-compatible` has none).
    pub fn default_base_url(&self) -> Option<&'static str> {
        match self {
            Self::Anthropic => Some(ANTHROPIC_BASE_URL),
            Self::OpenAi => Some(OPENAI_BASE_URL),
            Self::OpenAiCompatible => None,
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a secret comes from. A file is read again for every use, so a rotated Secret applies to
/// the next request. `Debug` never shows a key.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretSource {
    File(PathBuf),
    Text(String),
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(p) => f.debug_tuple("File").field(p).finish(),
            Self::Text(_) => f.write_str("Text(<redacted>)"),
        }
    }
}

impl SecretSource {
    /// The secret now: a file's contents without surrounding whitespace. The error names the
    /// file, never its contents.
    pub fn read(&self) -> Result<String, String> {
        match self {
            Self::Text(t) => Ok(t.clone()),
            Self::File(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("reading {}: {e}", path.display()))?;
                let text = text.trim();
                if text.is_empty() {
                    return Err(format!("{} is empty", path.display()));
                }
                Ok(text.to_string())
            }
        }
    }
}

/// A provider's endpoint and credential: one unit (a key is bound to the endpoint it was issued
/// for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConnection {
    pub kind: ProviderKind,
    /// Without a trailing `/`.
    pub base_url: String,
    /// `None`: no key (a local OpenAI-compatible server may need none).
    pub key: Option<SecretSource>,
}

/// Where the calls go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// To the provider itself.
    Provider(ProviderConnection),
    /// Gateway mode: to the platform's model gateway, in `wire`'s format.
    Gateway {
        /// The root URL, without a trailing `/` or `/v1`.
        root: String,
        token_file: PathBuf,
        wire: ProviderKind,
    },
}

/// An active contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    pub upstream: Upstream,
    pub model: String,
    pub model_small: Option<String>,
    pub timeout: Option<Duration>,
    pub max_retries: Option<u32>,
}

/// What [`Contract::from_env`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// `None`: the contract is off (neither `LLM_PROVIDER` nor `LLM_GATEWAY_URL` is set).
    pub contract: Option<Contract>,
    /// To log, one line each.
    pub warnings: Vec<String>,
}

fn http_url(var: &str, value: &str) -> Result<String, String> {
    match url::Url::parse(value) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host().is_some() => {
            Ok(value.trim_end_matches('/').to_string())
        }
        _ => Err(format!("{var} is invalid")),
    }
}

impl Contract {
    /// The contract from `get` (the process environment: [`Contract::from_process_env`]).
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Parsed, String> {
        let var = |name: &str| get(name).filter(|v| !v.trim().is_empty());
        let provider = var("LLM_PROVIDER");
        let gateway = var("LLM_GATEWAY_URL");
        if provider.is_none() && gateway.is_none() {
            let warnings = VARIABLES
                .iter()
                .filter(|n| var(n).is_some())
                .map(|n| format!("Ignoring {n} without LLM_PROVIDER or LLM_GATEWAY_URL"))
                .collect();
            return Ok(Parsed {
                contract: None,
                warnings,
            });
        }
        let kind = match &provider {
            None => None,
            Some(p) => Some(
                ProviderKind::parse(p.trim())
                    .ok_or_else(|| "LLM_PROVIDER is invalid".to_string())?,
            ),
        };
        let model = var("LLM_MODEL").ok_or("LLM_MODEL can't be blank")?;
        if model.chars().any(char::is_whitespace) {
            return Err("LLM_MODEL is invalid".into());
        }
        let model_small = var("LLM_MODEL_SMALL");
        if model_small
            .as_deref()
            .is_some_and(|m| m.chars().any(char::is_whitespace))
        {
            return Err("LLM_MODEL_SMALL is invalid".into());
        }
        let timeout = var("LLM_TIMEOUT_SECS")
            .map(|v| match v.trim().parse::<u64>() {
                Ok(n) if n > 0 => Ok(Duration::from_secs(n)),
                _ => Err("LLM_TIMEOUT_SECS is invalid".to_string()),
            })
            .transpose()?;
        let max_retries = var("LLM_MAX_RETRIES")
            .map(|v| match v.trim().parse::<u32>() {
                Ok(n) if n <= MAX_RETRIES => Ok(n),
                _ => Err("LLM_MAX_RETRIES is invalid".to_string()),
            })
            .transpose()?;
        let mut warnings = Vec::new();
        let key = match (var("LLM_API_KEY_FILE"), var("LLM_API_KEY")) {
            (Some(f), _) => Some(SecretSource::File(PathBuf::from(f.trim()))),
            (None, Some(k)) => Some(SecretSource::Text(k.trim().to_string())),
            (None, None) => None,
        };
        let upstream = match gateway {
            Some(g) => {
                let root = http_url("LLM_GATEWAY_URL", g.trim())?;
                let root = root
                    .strip_suffix("/v1")
                    .map(|r| r.trim_end_matches('/').to_string())
                    .unwrap_or(root);
                let token_file =
                    var("LLM_GATEWAY_TOKEN_FILE").ok_or("LLM_GATEWAY_TOKEN_FILE can't be blank")?;
                for ignored in ["LLM_API_KEY_FILE", "LLM_API_KEY", "LLM_BASE_URL"] {
                    if var(ignored).is_some() {
                        warnings.push(format!(
                            "Ignoring {ignored} in gateway mode (LLM_GATEWAY_URL is set)"
                        ));
                    }
                }
                Upstream::Gateway {
                    root,
                    token_file: PathBuf::from(token_file.trim()),
                    wire: kind.unwrap_or(ProviderKind::Anthropic),
                }
            }
            None => {
                let kind = kind.ok_or("LLM_PROVIDER is invalid")?;
                let base_url = match (var("LLM_BASE_URL"), kind.default_base_url()) {
                    (Some(b), _) => http_url("LLM_BASE_URL", b.trim())?,
                    (None, Some(d)) => d.to_string(),
                    (None, None) => return Err("LLM_BASE_URL can't be blank".into()),
                };
                Upstream::Provider(ProviderConnection {
                    kind,
                    base_url,
                    key,
                })
            }
        };
        Ok(Parsed {
            contract: Some(Contract {
                upstream,
                model: model.trim().to_string(),
                model_small: model_small.map(|m| m.trim().to_string()),
                timeout,
                max_retries,
            }),
            warnings,
        })
    }

    /// [`Contract::from_env`] on this process's environment.
    pub fn from_process_env() -> Result<Parsed, String> {
        Self::from_env(|name| std::env::var(name).ok())
    }

    /// One line for the start-up log: what the contract configures, never a secret.
    pub fn describe(&self) -> String {
        let to = match &self.upstream {
            Upstream::Provider(p) => format!(
                "provider {} at {}{}",
                p.kind,
                p.base_url,
                match &p.key {
                    Some(SecretSource::File(f)) => format!(", key from {}", f.display()),
                    Some(SecretSource::Text(_)) => ", key from LLM_API_KEY".to_string(),
                    None => ", no key".to_string(),
                }
            ),
            Upstream::Gateway {
                root,
                token_file,
                wire,
            } => format!(
                "the model gateway at {root} ({wire} wire format, token from {})",
                token_file.display()
            ),
        };
        format!("LLM connection contract v1: {to}, model {}", self.model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(vars: &[(&str, &str)]) -> Result<Parsed, String> {
        let env: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Contract::from_env(|k| env.get(k).cloned())
    }

    fn contract(vars: &[(&str, &str)]) -> Contract {
        parse(vars).unwrap().contract.unwrap()
    }

    #[test]
    fn nothing_set_changes_nothing_and_strays_are_ignored_with_a_warning() {
        assert_eq!(
            parse(&[]).unwrap(),
            Parsed {
                contract: None,
                warnings: vec![]
            }
        );
        let p = parse(&[
            ("LLM_MODEL", "claude-opus-5-5"),
            ("LLM_API_KEY", "sk-1"),
            ("LLM_PROVIDER", ""),
        ])
        .unwrap();
        assert_eq!(p.contract, None);
        assert_eq!(
            p.warnings,
            [
                "Ignoring LLM_API_KEY without LLM_PROVIDER or LLM_GATEWAY_URL",
                "Ignoring LLM_MODEL without LLM_PROVIDER or LLM_GATEWAY_URL"
            ]
        );
    }

    #[test]
    fn provider_mode_with_defaults_and_a_key_file_that_wins() {
        let c = contract(&[
            ("LLM_PROVIDER", "anthropic"),
            ("LLM_MODEL", "claude-opus-5-5"),
            ("LLM_API_KEY", "sk-text"),
            ("LLM_API_KEY_FILE", "/var/run/secrets/llm/api-key"),
            ("LLM_TIMEOUT_SECS", "120"),
            ("LLM_MAX_RETRIES", "3"),
        ]);
        assert_eq!(
            c.upstream,
            Upstream::Provider(ProviderConnection {
                kind: ProviderKind::Anthropic,
                base_url: ANTHROPIC_BASE_URL.into(),
                key: Some(SecretSource::File("/var/run/secrets/llm/api-key".into())),
            })
        );
        assert_eq!(c.timeout, Some(Duration::from_secs(120)));
        assert_eq!(c.max_retries, Some(3));
        let c = contract(&[("LLM_PROVIDER", "openai"), ("LLM_MODEL", "gpt-5")]);
        let Upstream::Provider(p) = c.upstream else {
            panic!()
        };
        assert_eq!((p.base_url.as_str(), p.key), (OPENAI_BASE_URL, None));
        let c = contract(&[
            ("LLM_PROVIDER", "openai-compatible"),
            ("LLM_BASE_URL", "http://localhost:11434/v1/"),
            ("LLM_MODEL", "llama3.3"),
        ]);
        let Upstream::Provider(p) = c.upstream else {
            panic!()
        };
        assert_eq!(p.base_url, "http://localhost:11434/v1", "http is allowed");
    }

    #[test]
    fn gateway_mode_ignores_a_trailing_v1_and_needs_the_token_file() {
        let c = contract(&[
            ("LLM_GATEWAY_URL", "https://gateway.agentsc.svc/v1/"),
            (
                "LLM_GATEWAY_TOKEN_FILE",
                "/var/run/secrets/llm/gateway-token",
            ),
            ("LLM_MODEL", "claude-opus-5-5"),
        ]);
        assert_eq!(
            c.upstream,
            Upstream::Gateway {
                root: "https://gateway.agentsc.svc".into(),
                token_file: "/var/run/secrets/llm/gateway-token".into(),
                wire: ProviderKind::Anthropic,
            }
        );
        let p = parse(&[
            ("LLM_GATEWAY_URL", "http://gw:8090"),
            ("LLM_GATEWAY_TOKEN_FILE", "/t"),
            ("LLM_PROVIDER", "openai"),
            ("LLM_API_KEY", "sk-stray"),
            ("LLM_MODEL", "gpt-5"),
        ])
        .unwrap();
        let Upstream::Gateway { wire, .. } = p.contract.unwrap().upstream else {
            panic!()
        };
        assert_eq!(
            wire,
            ProviderKind::OpenAi,
            "the provider picks the wire format"
        );
        assert_eq!(
            p.warnings,
            ["Ignoring LLM_API_KEY in gateway mode (LLM_GATEWAY_URL is set)"]
        );
        assert_eq!(
            parse(&[("LLM_GATEWAY_URL", "http://gw"), ("LLM_MODEL", "m")]).unwrap_err(),
            "LLM_GATEWAY_TOKEN_FILE can't be blank"
        );
    }

    #[test]
    fn errors_name_the_variable_and_never_the_key() {
        let key = "sk-ant-secret-0123456789";
        for (vars, want) in [
            (vec![("LLM_PROVIDER", "claude")], "LLM_PROVIDER is invalid"),
            (
                vec![("LLM_PROVIDER", "anthropic")],
                "LLM_MODEL can't be blank",
            ),
            (
                vec![("LLM_PROVIDER", "anthropic"), ("LLM_MODEL", "a b")],
                "LLM_MODEL is invalid",
            ),
            (
                vec![("LLM_PROVIDER", "openai-compatible"), ("LLM_MODEL", "m")],
                "LLM_BASE_URL can't be blank",
            ),
            (
                vec![
                    ("LLM_PROVIDER", "openai"),
                    ("LLM_MODEL", "m"),
                    ("LLM_BASE_URL", "ftp://x"),
                ],
                "LLM_BASE_URL is invalid",
            ),
            (
                vec![
                    ("LLM_PROVIDER", "openai"),
                    ("LLM_MODEL", "m"),
                    ("LLM_TIMEOUT_SECS", "0"),
                ],
                "LLM_TIMEOUT_SECS is invalid",
            ),
            (
                vec![
                    ("LLM_PROVIDER", "openai"),
                    ("LLM_MODEL", "m"),
                    ("LLM_MAX_RETRIES", "11"),
                ],
                "LLM_MAX_RETRIES is invalid",
            ),
            (
                vec![("LLM_GATEWAY_URL", "not a url"), ("LLM_MODEL", "m")],
                "LLM_GATEWAY_URL is invalid",
            ),
        ] {
            let mut vars = vars;
            vars.push(("LLM_API_KEY", key));
            let e = parse(&vars).unwrap_err();
            assert_eq!(e, want);
            assert!(!e.contains(key));
        }
        let c = contract(&[
            ("LLM_PROVIDER", "openai"),
            ("LLM_MODEL", "m"),
            ("LLM_API_KEY", key),
        ]);
        assert!(!format!("{c:?}").contains(key) && !c.describe().contains(key));
    }

    #[test]
    fn a_key_file_is_read_again_for_every_use() {
        let dir = std::env::temp_dir().join(format!("llm-contract-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api-key");
        let source = SecretSource::File(path.clone());
        assert!(source.read().unwrap_err().contains("api-key"));
        std::fs::write(&path, "sk-1\n").unwrap();
        assert_eq!(source.read().unwrap(), "sk-1");
        std::fs::write(&path, "sk-2").unwrap();
        assert_eq!(
            source.read().unwrap(),
            "sk-2",
            "a rotated Secret applies to the next use"
        );
        std::fs::write(&path, " \n").unwrap();
        assert!(source.read().unwrap_err().ends_with("is empty"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
