//! Tutela's decision next to embassy's own on charter writes: stage 1 of the shadow dual run
//! (Tutela `docs/INTEGRATION.md` §1, §3 step 3; design §8.3).
//!
//! - **The old check decides.** [`crate::api::write::write`] compares the caller's role with the
//!   role the diff needs. [`Shadow::compare`] runs next to it and only logs and counts.
//! - **The new check** asks `tutela-pdp` whether the caller holds every permission key of the diff
//!   ([`agentsc_charter::diff::Required::keys`]) on the service, under attache's manifest
//!   (`tutela.resources.toml`). The caller's role assignments are their role in each namespace
//!   they may reach: until `tutelad` holds assignments (Tutela Phase B, #24), attache's own
//!   configuration is the only source. So a mismatch points at the model, which is what stage 1
//!   is there to find.
//! - **Mismatches** go to the log with target `tutela.shadow` (opaque ids only, never names or
//!   tokens) and are counted per process: `GET /api/v1/authz/shadow`.
//!
//! Callers have no Tutela principal yet, so [`token_principal`] derives a stable one per token
//! name. The tenant and the org are embassy's own, private to this check. No token is verified
//! here and nothing leaves the process.
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use agentsc_common::principal::{Principal, uuid7_from_bytes};
use arc_swap::ArcSwapOption;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tutela_contracts::keys::{ActionKey, ResourceId, ResourceType};
use tutela_contracts::principal::{ServiceAccountId, UserId};
use tutela_contracts::tenant::{Issuer, OrgId, TenantId, TenantKey};
use tutela_pdp::model::{Model, RoleKey};
use tutela_pdp::{Attrs, Binding, CheckRequest, PathEntry, Pdp, ResourceRef, Subject, TenantData};

use crate::config::{ALL_NAMESPACES, Role};
use crate::store::ServiceKey;

/// attache's manifest.
pub const MANIFEST: &str = include_str!("../tutela.resources.toml");
/// The issuer of embassy's private tenant: a name, never contacted.
const ISSUER: &str = "https://embassy.attache.invalid";
/// The stage of the dual run this build is in.
pub const STAGE: &str = "shadow";
/// Mismatches kept for `GET /api/v1/authz/shadow`.
const RECENT: usize = 32;

/// A stable id in Tutela's form: the first 16 bytes of the SHA-256 of `parts`, with the UUIDv7
/// version and variant bits set.
fn derived_uuid(domain: &str, parts: &[&str]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    for p in parts {
        h.update([0u8]);
        h.update(p.as_bytes());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize()[..16]);
    out
}

/// The principal of the `att_` token named `name`: a service account, as Tutela's replacement for
/// these tokens will be.
pub fn token_principal(name: &str) -> Principal {
    let id = uuid7_from_bytes(derived_uuid("attache-token", &[name]));
    Principal::ServiceAccount(ServiceAccountId::new(id))
}

/// The principal of the person `sub` of issuer `iss`: `(iss, sub)` names them, never an e-mail
/// (Tutela CONTRACTS.md 4.6).
pub fn user_principal(iss: &str, sub: &str) -> Principal {
    let id = uuid7_from_bytes(derived_uuid("attache-user", &[iss, sub]));
    Principal::User(UserId::new(id))
}

/// Who a shadow check asks about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub principal: Principal,
    pub role: Role,
    /// `["*"]` = every namespace.
    pub namespaces: Vec<String>,
}

/// One difference between the two decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mismatch {
    pub at: String,
    pub principal: String,
    pub namespace: String,
    pub service: String,
    /// The permission keys asked.
    pub keys: Vec<String>,
    /// The keys Tutela denied.
    pub denied: Vec<String>,
    pub old: bool,
    pub new: bool,
}

/// `GET /api/v1/authz/shadow`: this process since it started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShadowReport {
    pub stage: &'static str,
    pub checks: u64,
    pub matches: u64,
    pub mismatches: u64,
    /// Checks Tutela could not answer. An error is never an allow, and is not a mismatch either.
    pub errors: u64,
    /// The newest mismatches, newest last.
    pub recent: Vec<Mismatch>,
}

/// What Tutela answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    pub denied: Vec<String>,
    pub rules: Vec<String>,
    pub rev: u64,
}

/// The dual run's state: one per process.
#[derive(Debug)]
pub struct Shadow {
    model: ArcSwapOption<Model>,
    tenant: Option<(TenantKey, OrgId)>,
    checks: AtomicU64,
    matches: AtomicU64,
    mismatches: AtomicU64,
    errors: AtomicU64,
    recent: Mutex<VecDeque<Mismatch>>,
}

impl Default for Shadow {
    fn default() -> Self {
        Self::new()
    }
}

impl Shadow {
    /// With attache's manifest. A failure here cannot change a decision, so it is logged and
    /// every check counts as an error.
    pub fn new() -> Self {
        let shadow = Shadow {
            model: ArcSwapOption::empty(),
            tenant: private_tenant(),
            checks: AtomicU64::new(0),
            matches: AtomicU64::new(0),
            mismatches: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            recent: Mutex::new(VecDeque::new()),
        };
        if let Err(e) = shadow.use_manifest(MANIFEST) {
            tracing::error!(target: "tutela.shadow", error = %e, "attache's manifest does not compile");
        }
        shadow
    }

    /// Check against `manifest` from now on.
    pub fn use_manifest(&self, manifest: &str) -> Result<(), String> {
        let model = Model::from_toml(manifest).map_err(|e| e.to_string())?;
        self.model.store(Some(Arc::new(model)));
        Ok(())
    }

    /// Whether `caller` holds every key on the service.
    pub fn decide(
        &self,
        caller: &Caller,
        keys: &BTreeSet<&'static str>,
        key: &ServiceKey,
    ) -> Result<Verdict, String> {
        let model = self.model.load_full().ok_or("no compiled model")?;
        let (tenant, org) = self.tenant.as_ref().ok_or("no tenant")?;
        let org_entry = PathEntry::org(org).map_err(|e| e.to_string())?;
        let namespace_entry = |ns: &str| -> Result<PathEntry, String> {
            Ok(PathEntry::new(
                type_of("namespace")?,
                ResourceId::parse(ns).map_err(|e| e.to_string())?,
            ))
        };
        let role = RoleKey::parse(caller.role.as_str()).map_err(|e| e.to_string())?;
        let mut bindings = Vec::new();
        let mut scopes = Vec::new();
        if caller.namespaces.iter().any(|n| n == ALL_NAMESPACES) {
            scopes.push(org_entry.clone());
        } else {
            for ns in &caller.namespaces {
                scopes.push(namespace_entry(ns)?);
            }
        }
        for (i, scope) in scopes.into_iter().enumerate() {
            bindings.push(Binding {
                id: tutela_contracts::decision::RuleId::parse(&format!("ra_{i}"))
                    .map_err(|e| e.to_string())?,
                subject: Subject::Principal(caller.principal.clone()),
                role: role.clone(),
                scope,
            });
        }
        let data = TenantData {
            orgs: [*org].into(),
            bindings,
            groups: Vec::new(),
            private_scopes: BTreeSet::new(),
            field_rules: Vec::new(),
        };
        let mut pdp = Pdp::new();
        pdp.load(tenant.clone(), 1, model, data)
            .map_err(|e| e.to_string())?;
        let resource = ResourceRef {
            type_name: type_of("service")?,
            id: ResourceId::parse(&key.service).map_err(|e| e.to_string())?,
            path: vec![namespace_entry(&key.namespace)?, org_entry],
            attrs: Attrs::new(),
        };
        let wanted: Vec<&str> = keys.iter().copied().collect();
        let requests = wanted
            .iter()
            .map(|k| {
                Ok(CheckRequest {
                    tenant: tenant.clone(),
                    subject: caller.principal.clone(),
                    actors: Vec::new(),
                    action: ActionKey::parse(k).map_err(|e| e.to_string())?,
                    resource: resource.clone(),
                    fields: None,
                    at_least_revision: None,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let decisions = pdp.batch(&requests).map_err(|e| e.to_string())?;
        let denied: Vec<String> = wanted
            .iter()
            .zip(&decisions)
            .filter(|(_, d)| !d.is_allowed())
            .map(|(k, _)| (*k).to_string())
            .collect();
        let rules: BTreeSet<String> = decisions
            .iter()
            .flat_map(|d| d.rule_ids.iter().map(|r| r.as_str().to_string()))
            .collect();
        Ok(Verdict {
            allowed: denied.is_empty() && !decisions.is_empty(),
            denied,
            rules: rules.into_iter().collect(),
            rev: decisions.first().map_or(0, |d| d.rev),
        })
    }

    /// Run the new check next to the `old` decision, log it and count it. Changes nothing.
    pub fn compare(
        &self,
        caller: &Caller,
        keys: &BTreeSet<&'static str>,
        key: &ServiceKey,
        old: bool,
    ) {
        self.checks.fetch_add(1, Ordering::Relaxed);
        let verdict = match self.decide(caller, keys, key) {
            Ok(v) => v,
            Err(error) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "tutela.shadow",
                    principal = %caller.principal,
                    resource_id = %key,
                    old,
                    error,
                    "Tutela could not answer"
                );
                return;
            }
        };
        if verdict.allowed == old {
            self.matches.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                target: "tutela.shadow",
                principal = %caller.principal,
                resource_id = %key,
                decision = old,
                rev = verdict.rev,
                "the decisions agree"
            );
            return;
        }
        self.mismatches.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            target: "tutela.shadow",
            action = "charter:write",
            principal = %caller.principal,
            resource_id = %key,
            keys = ?keys,
            denied = ?verdict.denied,
            old,
            new = verdict.allowed,
            rules = ?verdict.rules,
            rev = verdict.rev,
            "the decisions differ"
        );
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        if recent.len() == RECENT {
            recent.pop_front();
        }
        recent.push_back(Mismatch {
            at: crate::cp_audit::now_ts(),
            principal: caller.principal.to_string(),
            namespace: key.namespace.clone(),
            service: key.service.clone(),
            keys: keys.iter().map(|k| (*k).to_string()).collect(),
            denied: verdict.denied,
            old,
            new: verdict.allowed,
        });
    }

    pub fn report(&self) -> ShadowReport {
        ShadowReport {
            stage: STAGE,
            checks: self.checks.load(Ordering::Relaxed),
            matches: self.matches.load(Ordering::Relaxed),
            mismatches: self.mismatches.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            recent: self
                .recent
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .cloned()
                .collect(),
        }
    }
}

fn type_of(name: &str) -> Result<ResourceType, String> {
    ResourceType::parse(name).map_err(|e| e.to_string())
}

/// The tenant and org of the private bundle, named by [`ISSUER`].
fn private_tenant() -> Option<(TenantKey, OrgId)> {
    let issuer = Issuer::parse(ISSUER).ok()?;
    let tid = TenantId::new(uuid7_from_bytes(derived_uuid("attache-tenant", &[ISSUER])));
    let org = OrgId::new(uuid7_from_bytes(derived_uuid("attache-org", &[ISSUER])));
    Some((TenantKey::new(issuer, tid), org))
}

#[cfg(test)]
mod tests {
    use agentsc_charter::diff::perm;

    use super::*;

    fn key() -> ServiceKey {
        ServiceKey {
            namespace: "shop".into(),
            service: "orders".into(),
        }
    }

    fn caller(role: Role, namespaces: &[&str]) -> Caller {
        Caller {
            principal: token_principal("alice"),
            role,
            namespaces: namespaces.iter().map(|n| (*n).to_string()).collect(),
        }
    }

    fn keys(k: &[&'static str]) -> BTreeSet<&'static str> {
        k.iter().copied().collect()
    }

    #[test]
    fn the_manifest_declares_exactly_the_keys_the_diff_names() {
        let declared: BTreeSet<String> = MANIFEST
            .lines()
            .filter_map(|l| l.trim().split_once(" = { needs = \"write\" }"))
            .chain(
                MANIFEST
                    .lines()
                    .filter_map(|l| l.trim().split_once("= { needs = \"write\" }")),
            )
            .map(|(name, _)| format!("service:{}", name.trim()))
            .collect();
        let named: BTreeSet<String> = perm::ADMIN_KEYS.iter().map(|k| (*k).to_string()).collect();
        assert_eq!(declared, named);
        for k in perm::ADMIN_KEYS {
            assert!(MANIFEST.contains(&format!("\"{k}\"")), "admin holds {k}");
        }
    }

    #[test]
    fn the_model_gives_each_role_what_the_old_check_gives_it() {
        let shadow = Shadow::new();
        assert!(shadow.report().errors == 0);
        let write = keys(&[perm::WRITE]);
        for (role, write_ok, admin_ok) in [
            (Role::Viewer, false, false),
            (Role::Editor, true, false),
            (Role::Admin, true, true),
        ] {
            let c = caller(role, &["*"]);
            let v = shadow.decide(&c, &write, &key()).unwrap();
            assert_eq!(v.allowed, write_ok, "{role:?} {v:?}");
            for k in perm::ADMIN_KEYS {
                let v = shadow.decide(&c, &keys(&[perm::WRITE, k]), &key()).unwrap();
                assert_eq!(v.allowed, admin_ok, "{role:?} {k}");
            }
        }
    }

    #[test]
    fn a_role_reaches_only_its_namespaces() {
        let shadow = Shadow::new();
        let write = keys(&[perm::WRITE]);
        let inside = caller(Role::Admin, &["shop"]);
        assert!(shadow.decide(&inside, &write, &key()).unwrap().allowed);
        let outside = caller(Role::Admin, &["billing"]);
        let v = shadow.decide(&outside, &write, &key()).unwrap();
        assert!(!v.allowed);
        assert_eq!(v.denied, [perm::WRITE]);
    }

    #[test]
    fn a_broken_model_is_counted_and_logged_and_decides_nothing() {
        let shadow = Shadow::new();
        // editors lose write: the old check said yes, the model says no
        shadow
            .use_manifest(&MANIFEST.replace(
                "grants = { namespace = \"read\", service = \"write\" }",
                "grants = { namespace = \"read\", service = \"read\" }",
            ))
            .unwrap();
        let c = caller(Role::Editor, &["*"]);
        shadow.compare(&c, &keys(&[perm::WRITE]), &key(), true);
        shadow.compare(&c, &keys(&[perm::WRITE]), &key(), false);
        let r = shadow.report();
        assert_eq!((r.checks, r.matches, r.mismatches, r.errors), (2, 1, 1, 0));
        let m = &r.recent[0];
        assert!(m.old && !m.new);
        assert_eq!(m.denied, [perm::WRITE]);
        assert_eq!(m.principal, token_principal("alice").to_string());
    }

    #[test]
    fn an_unknown_key_is_an_error_and_never_an_allow() {
        let shadow = Shadow::new();
        let c = caller(Role::Admin, &["*"]);
        shadow.compare(&c, &keys(&["service:no_such_action"]), &key(), true);
        let r = shadow.report();
        assert_eq!((r.checks, r.matches, r.mismatches, r.errors), (1, 0, 0, 1));
    }

    #[test]
    fn derived_principals_are_stable_and_distinct() {
        assert_eq!(token_principal("a"), token_principal("a"));
        assert_ne!(token_principal("a"), token_principal("b"));
        assert_eq!(user_principal("i", "s"), user_principal("i", "s"));
        // the parts cannot run together
        assert_ne!(user_principal("ab", "c"), user_principal("a", "bc"));
        assert!(token_principal("a").to_string().starts_with("sa:sa_"));
        assert!(
            user_principal("i", "s")
                .to_string()
                .starts_with("user:usr_")
        );
    }
}
