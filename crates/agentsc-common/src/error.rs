//! Reporting errors. `Display` of an error is its own message and never its source: reporters walk
//! `source()`, so a message that repeated it would print it twice.

use std::error::Error;

/// `e` and every error under it on one line, `outer: inner: root`. An `anyhow::Error` prints this
/// with `{:#}`; a `thiserror` type ignores the flag, so its reporters call this.
///
/// Check what is under `e` before you add a call. A `tokio_postgres::Error` must never come through
/// here: its source is the server's `DbError`, whose `DETAIL` line holds row values.
pub fn chain(e: &(dyn Error + 'static)) -> String {
    let mut text = e.to_string();
    let mut next = e.source();
    while let Some(cause) = next {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        next = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsc_charter::{Charter, CharterError};

    #[derive(Debug, thiserror::Error)]
    enum Outer {
        #[error("outer")]
        Middle(#[source] Middle),
    }

    #[derive(Debug, thiserror::Error)]
    #[error("middle")]
    struct Middle(#[source] std::io::Error);

    #[test]
    fn every_message_comes_once_in_order() {
        let root = std::io::Error::other("root");
        assert_eq!(chain(&Outer::Middle(Middle(root))), "outer: middle: root");
        assert_eq!(chain(&std::io::Error::other("alone")), "alone");
    }

    /// What a reader sees of a charter that does not parse stays what it was before the message
    /// stopped repeating its source: the reason and where.
    #[test]
    fn a_charter_error_keeps_the_parser_message() {
        let e = Charter::from_yaml("apiVersion: agentsc.io/v1alpha1\nkind: Charter\nextra: 1\n")
            .unwrap_err();
        assert!(matches!(e, CharterError::Parse(_)), "{e:?}");
        assert_eq!(
            e.to_string(),
            "charter is not valid YAML or has unknown fields"
        );
        let text = chain(&e);
        assert!(
            text.starts_with("charter is not valid YAML or has unknown fields: "),
            "{text}"
        );
        assert!(text.contains("unknown field `extra`"), "{text}");
        assert_eq!(text.matches("unknown field `extra`").count(), 1, "{text}");
    }
}
