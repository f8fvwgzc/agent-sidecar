//! Input/output guardrails (CONTRACT.md §3, §5.1 steps 3 and 5).
use agentsc_charter::Guardrails;
use regex::Regex;

use crate::authz::Verdict;

/// Rule prefixes of the content rules. A payload one of them matched is withheld from the audit
/// log (hash kept): it is the payload most likely to carry the secret the rule looks for.
pub const INPUT_DENY: &str = "guardrail.input_deny.";
pub const OUTPUT_DENY: &str = "guardrail.output_deny.";

pub struct CompiledGuardrails {
    pub max_input_bytes: usize,
    pub pii_redact: bool,
    input_deny: Vec<(String, Regex)>,
    output_deny: Vec<(String, Regex)>,
}

static EMAIL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b").unwrap()
});
static PHONE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // +1 555 123 4567, (555) 123-4567, 555-123-4567 — at least 10 digits; the regex crate has no look-around.
    Regex::new(r"(\+\d{1,3}[\s.-]?)?(\(\d{3}\)[\s.-]?|\b\d{3}[\s.-]?)\d{3}[\s.-]?\d{4}\b").unwrap()
});

impl CompiledGuardrails {
    pub fn compile(g: &Guardrails) -> Result<Self, regex::Error> {
        let compile = |rules: &Vec<agentsc_charter::RegexRule>| {
            rules
                .iter()
                .map(|r| Regex::new(&r.regex).map(|re| (r.name.clone(), re)))
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            max_input_bytes: g.max_input_bytes,
            pii_redact: g.pii_redact,
            input_deny: compile(&g.input_deny)?,
            output_deny: compile(&g.output_deny)?,
        })
    }

    pub fn check_input(&self, input: &str) -> Verdict {
        self.check_input_with_context(input, "")
    }

    /// Everything the model will see on the first turn: the input and the `context` JSON.
    pub fn check_input_with_context(&self, input: &str, context: &str) -> Verdict {
        let size = input.len() + context.len();
        if size > self.max_input_bytes {
            return Verdict::deny(
                "guardrail.max_input_bytes",
                format!(
                    "input and context are {size} bytes, limit {}",
                    self.max_input_bytes
                ),
            );
        }
        for (name, re) in &self.input_deny {
            if re.is_match(input) || (!context.is_empty() && re.is_match(context)) {
                return Verdict::deny(
                    format!("{INPUT_DENY}{name}"),
                    format!("input matches deny rule {name}"),
                );
            }
        }
        Verdict::allow("guardrail.input")
    }

    pub fn check_output(&self, output: &str) -> Verdict {
        for (name, re) in &self.output_deny {
            if re.is_match(output) {
                return Verdict::deny(
                    format!("{OUTPUT_DENY}{name}"),
                    format!("output matches deny rule {name}"),
                );
            }
        }
        Verdict::allow("guardrail.output")
    }

    /// Returns the rewritten output and the number of replacements (0 = untouched).
    pub fn redact_pii(&self, output: &str) -> (String, usize) {
        if !self.pii_redact {
            return (output.to_string(), 0);
        }
        redact_pii(output)
    }
}

pub fn redact_pii(text: &str) -> (String, usize) {
    let mut n = 0;
    let s = EMAIL.replace_all(text, |_: &regex::Captures| {
        n += 1;
        "[redacted:email]"
    });
    let s = PHONE.replace_all(&s, |_: &regex::Captures| {
        n += 1;
        "[redacted:phone]"
    });
    (s.into_owned(), n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_emails_and_phones() {
        let (s, n) =
            redact_pii("contact ops-lead@example.com or +1 555-123-4567; sku WIDGET-1 qty 42");
        assert_eq!(
            s,
            "contact [redacted:email] or [redacted:phone]; sku WIDGET-1 qty 42"
        );
        assert_eq!(n, 2);
        let (s, n) = redact_pii("order 1001 has 3 units");
        assert_eq!(n, 0);
        assert_eq!(s, "order 1001 has 3 units");
    }

    #[test]
    fn input_rules() {
        let g = Guardrails {
            max_input_bytes: 10,
            input_deny: vec![agentsc_charter::RegexRule {
                name: "no-secrets".into(),
                regex: "(?i)password\\s*[:=]".into(),
            }],
            ..Default::default()
        };
        let c = CompiledGuardrails::compile(&g).unwrap();
        assert_eq!(
            c.check_input("12345678901").rule,
            "guardrail.max_input_bytes"
        );
        assert_eq!(c.check_input("pw: x").rule, "guardrail.input");
        let g2 = Guardrails {
            max_input_bytes: 1000,
            ..g
        };
        let c2 = CompiledGuardrails::compile(&g2).unwrap();
        assert_eq!(
            c2.check_input("my Password = hunter2").rule,
            "guardrail.input_deny.no-secrets"
        );
        // the context goes to the model too, so it is checked too
        assert_eq!(
            c2.check_input_with_context("hi", r#"{"note":"password: x"}"#)
                .rule,
            "guardrail.input_deny.no-secrets"
        );
        assert_eq!(
            c2.check_input_with_context("hi", &"y".repeat(1000)).rule,
            "guardrail.max_input_bytes"
        );
    }
}
