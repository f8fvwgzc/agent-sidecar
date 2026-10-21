//! The `Charter` custom resource form (design §4): `apiVersion: attache.io/v1alpha1`,
//! `kind: Charter`, `metadata: {name, namespace}`, `spec: <the charter without apiVersion/kind>`.
//!
//! `metadata.name` must equal `spec.service.name`; `spec.service.namespace` is optional and
//! defaults to `metadata.namespace` (if both are given they must be equal). Other `metadata`
//! fields (labels, annotations, uid, …) are kept as they are; `status` is written by embassy and
//! ignored when the charter is read. Unknown fields anywhere else are errors, as in the plain form.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AgentSpec, AuditSpec, Authz, Charter, CharterError, DNS_LABEL_PATTERN, Guardrails, MeshSpec,
    ServiceSpec, SkillSpec, TelemetrySpec,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CharterResource {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: ObjectMeta,
    pub spec: CharterSpec,
    /// Written by embassy only (status subresource); never part of the charter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Value>,
}

/// The parts of Kubernetes `ObjectMeta` the charter reads; every other field is kept as-is.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ObjectMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(flatten)]
    pub other: serde_json::Map<String, Value>,
}

/// `spec` of a `Charter` custom resource: the plain charter without `apiVersion` and `kind`.
/// Keep the fields in step with [`Charter`] (a test compares the two).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CharterSpec {
    pub service: ResourceServiceSpec,
    #[serde(default)]
    pub mesh: MeshSpec,
    /// Skills agents can use (`agents[].skills`), by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub skills: Vec<SkillSpec>,
    #[serde(default)]
    pub agents: Vec<AgentSpec>,
    #[serde(default)]
    pub guardrails: Guardrails,
    #[serde(default)]
    pub authz: Authz,
    #[serde(default)]
    pub audit: AuditSpec,
    /// OpenTelemetry export and what audit leaves the pod. Absent = the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<TelemetrySpec>,
}

/// The service, as in the plain charter except that `namespace` is optional (it defaults to
/// `metadata.namespace`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceServiceSpec {
    /// DNS-1123 label; must equal `metadata.name`.
    pub name: String,
    /// Defaults to `metadata.namespace`; if given, must equal it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Port the app container listens on (localhost), target of inbound service invocations.
    pub app_port: u16,
    /// Kubernetes service accounts whose pods may obtain this identity, besides `<service.name>`
    /// (default: `[<service.name>]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(inner(pattern(DNS_LABEL_PATTERN)))]
    pub service_accounts: Vec<String>,
}

/// Is this JSON document the custom resource form (it has `spec` or `metadata`)?
pub fn is_resource(doc: &Value) -> bool {
    doc.as_object()
        .is_some_and(|m| m.contains_key("spec") || m.contains_key("metadata"))
}

/// [`is_resource`] for a YAML document.
pub fn is_resource_yaml(doc: &serde_yaml_ng::Value) -> bool {
    doc.as_mapping()
        .is_some_and(|m| m.contains_key("spec") || m.contains_key("metadata"))
}

/// May this YAML (or JSON) text be the custom resource form? Judged without parsing it, so that
/// [`Charter::from_yaml`] refuses a plain charter over [`crate::MAX_CHARTER_BYTES`] before the
/// parser sees it, while a resource (whose `status` may be much bigger) is still parsed.
///
/// Yes when `spec` or `metadata` is followed, after an optional closing quote and whitespace, by
/// `:` anywhere in the text: that covers the key in block YAML, flow YAML and JSON, minified or
/// not. It errs towards yes (the words in a system prompt count too; the text is then parsed, up
/// to [`crate::MAX_RESOURCE_BYTES`], and its form decided properly) and says no only for a text
/// that has neither key, or writes it with escapes (`"sp\x65c"`). Linear in the text's length.
pub fn may_be_resource_text(text: &str) -> bool {
    ["spec", "metadata"].iter().any(|key| {
        text.match_indices(key).any(|(at, _)| {
            text[at + key.len()..]
                .trim_start_matches(['"', '\''])
                .trim_start()
                .starts_with(':')
        })
    })
}

impl CharterResource {
    /// The custom resource of a charter: `metadata: {name, namespace}` from `service`, and
    /// `spec.service` without `namespace` (it lives in `metadata`).
    pub fn from_charter(c: &Charter) -> CharterResource {
        CharterResource {
            api_version: c.api_version.clone(),
            kind: c.kind.clone(),
            metadata: ObjectMeta {
                name: Some(c.service.name.clone()),
                namespace: Some(c.service.namespace.clone()),
                other: serde_json::Map::new(),
            },
            spec: CharterSpec {
                service: ResourceServiceSpec {
                    name: c.service.name.clone(),
                    namespace: None,
                    app_port: c.service.app_port,
                    service_accounts: c.service.service_accounts.clone(),
                },
                mesh: c.mesh.clone(),
                skills: c.skills.clone(),
                agents: c.agents.clone(),
                guardrails: c.guardrails.clone(),
                authz: c.authz.clone(),
                audit: c.audit.clone(),
                telemetry: c.telemetry.clone(),
            },
            status: None,
        }
    }

    /// The plain charter (not yet validated): `metadata.name` must equal `spec.service.name`, and
    /// the namespace comes from `spec.service.namespace` or `metadata.namespace` (equal if both).
    pub fn into_charter(self) -> Result<Charter, CharterError> {
        let mut errs = Vec::new();
        let svc = self.spec.service;
        match &self.metadata.name {
            None => errs.push("metadata.name is required (it must equal spec.service.name)".into()),
            Some(n) if n != &svc.name => errs.push(format!(
                "metadata.name {n:?} must equal spec.service.name {:?}",
                svc.name
            )),
            Some(_) => {}
        }
        let namespace = match (svc.namespace, self.metadata.namespace) {
            (Some(a), Some(b)) => {
                if a != b {
                    errs.push(format!(
                        "spec.service.namespace {a:?} must equal metadata.namespace {b:?}"
                    ));
                }
                a
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => {
                errs.push("spec.service.namespace or metadata.namespace is required".into());
                String::new()
            }
        };
        if !errs.is_empty() {
            return Err(CharterError::Invalid(errs));
        }
        Ok(Charter {
            api_version: self.api_version,
            kind: self.kind,
            service: ServiceSpec {
                name: svc.name,
                namespace,
                app_port: svc.app_port,
                service_accounts: svc.service_accounts,
            },
            mesh: self.spec.mesh,
            skills: self.spec.skills,
            agents: self.spec.agents,
            guardrails: self.spec.guardrails,
            authz: self.spec.authz,
            audit: self.spec.audit,
            telemetry: self.spec.telemetry,
        })
    }

    /// The resource as a YAML document (what `attache charter to-cr` prints).
    pub fn to_yaml(&self) -> Result<String, CharterError> {
        Ok(serde_yaml_ng::to_string(self)?)
    }
}
