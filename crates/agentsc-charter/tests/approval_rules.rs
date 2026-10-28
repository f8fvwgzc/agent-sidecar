//! `tools[].approval` (schema level 7, CONTRACT.md §5.4): the default and the range, the level,
//! and what a change of it needs and weakens.
mod common;

use agentsc_charter::diff::{Role, required_role, weakened};
use agentsc_charter::*;
use common::*;

fn with_approval(timeout_s: Option<u32>) -> Charter {
    let mut c = orders();
    let yaml = match timeout_s {
        Some(t) => format!("{{timeout_s: {t}}}"),
        None => "{}".into(),
    };
    c.agents[0].tools[0].approval = Some(serde_yaml_ng::from_str(&yaml).unwrap());
    c
}

#[test]
fn an_approval_has_a_timeout_of_1_to_86400_seconds_600_by_default() {
    let c = with_approval(None);
    accepts(&c);
    assert_eq!(
        c.agents[0].tools[0].approval.as_ref().unwrap().timeout_s,
        600
    );
    accepts(&with_approval(Some(1)));
    accepts(&with_approval(Some(86_400)));
    rejects(
        &with_approval(Some(0)),
        "approval.timeout_s must be 1..=86400",
    );
    rejects(
        &with_approval(Some(86_401)),
        "approval.timeout_s must be 1..=86400",
    );
    // unknown fields are errors
    let bad: Result<ApprovalSpec, _> = serde_yaml_ng::from_str("{timeout_s: 5, approvers: [x]}");
    assert!(bad.is_err());
}

#[test]
fn an_approval_makes_the_charter_level_7() {
    let c = with_approval(None);
    let tool = &c.agents[0].tools[0].name;
    assert_eq!(c.schema_level(), 7);
    assert!(
        c.level_fields()
            .contains(&(format!("agents.{}.tools.{tool}", c.agents[0].name), 7))
    );
    // it round trips, and a charter without one serializes as before
    let back = Charter::from_yaml(&c.to_yaml().unwrap()).unwrap();
    assert_eq!(
        back.agents[0].tools[0].approval,
        c.agents[0].tools[0].approval
    );
    assert!(!orders().to_yaml().unwrap().contains("approval"));
}

#[test]
fn only_an_admin_changes_an_approval_and_dropping_one_weakens() {
    let (plain, held) = (orders(), with_approval(None));
    let path = format!(
        "agents.{}.tools.{}",
        plain.agents[0].name, plain.agents[0].tools[0].name
    );
    for (old, new) in [
        (&plain, &held),
        (&held, &plain),
        (&held, &with_approval(Some(30))),
    ] {
        let (role, why) = required_role(old, new);
        assert_eq!(role, Role::Admin, "{why:?}");
        assert!(
            why.iter()
                .any(|w| w == &format!("{path} approval requires admin")),
            "{why:?}"
        );
    }
    assert_eq!(weakened(&held, &plain), [format!("{path}.approval")]);
    assert!(weakened(&plain, &held).is_empty());
}
