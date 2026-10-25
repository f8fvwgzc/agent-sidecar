//! The Kubernetes API calls embassy makes, behind two traits so that everything above them runs
//! in tests without a cluster:
//!
//! - [`KubeApi`]: TokenReview and pod lookups for `IssueCertificate` (design §7), the CA and
//!   serving-certificate Secrets, and the two webhook configurations whose `caBundle` is kept
//!   current (design §13);
//! - [`CharterApi`]: `Charter` custom resources (with their `status` subresource), the
//!   `apps/v1 ControllerRevision`s that hold their history (design §8.4), and the ConfigMaps
//!   that hold the control-plane audit (design §8.5, [`super::cp_audit_log`]).
//!
//! [`KubeClient`] implements both over a `kube::Client`; the RBAC it needs is exactly the chart's
//! (`deploy/helm/agent-sidecar/templates/rbac.yaml`): no `list` on Secrets or webhook
//! configurations, `get`/`update` on Secrets by name, and on ConfigMaps only `get`/`update` of
//! the audit segments by name plus `create`, in the control-plane namespace.
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::ControllerRevision;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus};
use k8s_openapi::api::core::v1::{ConfigMap, Pod, Secret};
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, GroupVersionKind, ListParams, Patch,
    PatchParams, PostParams, Preconditions,
};
use serde_json::Value;

/// The field manager of every write embassy makes (`metadata.managedFields[].manager`); the
/// store tells its own writes from kubectl's by it.
pub const FIELD_MANAGER: &str = "embassy";
/// `Charter` custom resources: group, version, kind, plural.
pub const CHARTER_GROUP: &str = "agentsc.io";
pub const CHARTER_VERSION: &str = "v1alpha1";
pub const CHARTER_KIND: &str = "Charter";
pub const CHARTER_PLURAL: &str = "charters";

/// A failed Kubernetes API call, by what the caller does about it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// 404.
    #[error("not found")]
    NotFound,
    /// 409 `AlreadyExists` (a create lost a race).
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// 409 `Conflict` (a stale `resourceVersion`): read again and retry.
    #[error("conflict: {0}")]
    Conflict(String),
    /// 400, 403 or 422: the API server or an admission webhook refused the object.
    #[error("refused: {0}")]
    Refused(String),
    /// Anything else (network, 5xx, decoding).
    #[error("{0}")]
    Other(String),
}

impl From<kube::Error> for ApiError {
    fn from(e: kube::Error) -> Self {
        match e {
            kube::Error::Api(s) => match s.code {
                404 => ApiError::NotFound,
                409 if s.reason == "AlreadyExists" => ApiError::AlreadyExists(s.message),
                409 => ApiError::Conflict(s.message),
                400 | 403 | 422 => ApiError::Refused(s.message),
                code => ApiError::Other(format!("HTTP {code}: {}", s.message)),
            },
            other => ApiError::Other(other.to_string()),
        }
    }
}

/// `get` that maps 404 to `None`.
fn optional<T>(r: Result<T, ApiError>) -> Result<Option<T>, ApiError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(ApiError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Which admission configuration (design §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebhookKind {
    /// `admissionregistration.k8s.io/v1 MutatingWebhookConfiguration` (the injector).
    Mutating,
    /// `admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration` (the charter validator).
    Validating,
}

/// Cluster calls of the `ca` and `webhook` components.
#[async_trait]
pub trait KubeApi: Send + Sync {
    /// `POST authentication.k8s.io/v1 TokenReview` with `spec.audiences`.
    async fn token_review(
        &self,
        token: &str,
        audiences: &[String],
    ) -> Result<TokenReviewStatus, ApiError>;
    /// `GET pods/<name>` in `namespace`; `None` when there is no such pod.
    async fn get_pod(&self, namespace: &str, name: &str) -> Result<Option<Pod>, ApiError>;
    async fn get_secret(&self, namespace: &str, name: &str) -> Result<Option<Secret>, ApiError>;
    async fn create_secret(&self, namespace: &str, secret: &Secret) -> Result<Secret, ApiError>;
    /// `PUT` with the `resourceVersion` in `secret.metadata` (a stale one is a conflict).
    async fn replace_secret(&self, namespace: &str, secret: &Secret) -> Result<Secret, ApiError>;
    /// The live webhook configuration as JSON; `None` when it does not exist.
    async fn get_webhook_config(
        &self,
        kind: WebhookKind,
        name: &str,
    ) -> Result<Option<Value>, ApiError>;
    /// A strategic-merge patch of the webhook configuration.
    async fn patch_webhook_config(
        &self,
        kind: WebhookKind,
        name: &str,
        patch: &Value,
    ) -> Result<(), ApiError>;
}

/// `Charter` resources (as JSON: the store keeps every field it does not know), their
/// `ControllerRevision`s, and the control-plane audit ConfigMaps.
#[async_trait]
pub trait CharterApi: Send + Sync {
    async fn get(&self, namespace: &str, name: &str) -> Result<Option<Value>, ApiError>;
    /// Every Charter in every namespace.
    async fn list(&self) -> Result<Vec<Value>, ApiError>;
    /// Create; `status` is ignored (it is a subresource).
    async fn create(&self, namespace: &str, object: &Value) -> Result<Value, ApiError>;
    /// Replace `metadata` and `spec` with the `resourceVersion` in `object` (a stale one is a
    /// conflict); `status` is ignored.
    async fn replace(&self, namespace: &str, name: &str, object: &Value)
    -> Result<Value, ApiError>;
    /// Replace `status` only, with the `resourceVersion` in `object`.
    async fn replace_status(
        &self,
        namespace: &str,
        name: &str,
        object: &Value,
    ) -> Result<Value, ApiError>;
    /// Delete if the object still has `resource_version`.
    async fn delete(
        &self,
        namespace: &str,
        name: &str,
        resource_version: &str,
    ) -> Result<(), ApiError>;
    async fn list_revisions(
        &self,
        namespace: &str,
        label_selector: &str,
    ) -> Result<Vec<ControllerRevision>, ApiError>;
    async fn get_revision(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ControllerRevision>, ApiError>;
    async fn create_revision(
        &self,
        namespace: &str,
        revision: &ControllerRevision,
    ) -> Result<ControllerRevision, ApiError>;
    async fn delete_revision(&self, namespace: &str, name: &str) -> Result<(), ApiError>;
    /// `GET configmaps/<name>`; `None` when there is none.
    async fn get_config_map(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ConfigMap>, ApiError>;
    async fn create_config_map(
        &self,
        namespace: &str,
        config_map: &ConfigMap,
    ) -> Result<ConfigMap, ApiError>;
    /// `PUT` with the `resourceVersion` in `config_map.metadata` (a stale one is a conflict).
    async fn replace_config_map(
        &self,
        namespace: &str,
        config_map: &ConfigMap,
    ) -> Result<ConfigMap, ApiError>;
}

/// The `ApiResource` of `charters.agentsc.io/v1alpha1`.
pub fn charter_resource() -> ApiResource {
    ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk(CHARTER_GROUP, CHARTER_VERSION, CHARTER_KIND),
        CHARTER_PLURAL,
    )
}

/// [`KubeApi`] and [`CharterApi`] over a real cluster.
#[derive(Clone)]
pub struct KubeClient {
    client: kube::Client,
    charters: ApiResource,
}

impl std::fmt::Debug for KubeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeClient").finish_non_exhaustive()
    }
}

impl KubeClient {
    pub fn new(client: kube::Client) -> Self {
        Self {
            client,
            charters: charter_resource(),
        }
    }

    /// The in-cluster configuration (or the local kubeconfig).
    ///
    /// kube-rs takes rustls' process-wide default crypto provider, which rustls cannot pick by
    /// itself when more than one provider is compiled in (the workspace has `ring`; other
    /// dependencies bring `aws-lc-rs`): `ring` is installed unless a default exists already.
    pub async fn try_default() -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = kube::Client::try_default()
            .await
            .map_err(|e| anyhow::anyhow!("connect to the Kubernetes API: {e}"))?;
        Ok(Self::new(client))
    }

    pub fn client(&self) -> &kube::Client {
        &self.client
    }

    fn charters(&self, namespace: &str) -> Api<DynamicObject> {
        Api::namespaced_with(self.client.clone(), namespace, &self.charters)
    }

    fn revisions(&self, namespace: &str) -> Api<ControllerRevision> {
        Api::namespaced(self.client.clone(), namespace)
    }

    fn config_maps(&self, namespace: &str) -> Api<ConfigMap> {
        Api::namespaced(self.client.clone(), namespace)
    }

    fn post_params() -> PostParams {
        PostParams {
            dry_run: false,
            field_manager: Some(FIELD_MANAGER.to_string()),
        }
    }
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value, ApiError> {
    serde_json::to_value(v).map_err(|e| ApiError::Other(format!("encode: {e}")))
}

fn from_value<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, ApiError> {
    T::deserialize(v).map_err(|e| ApiError::Other(format!("decode: {e}")))
}

#[async_trait]
impl KubeApi for KubeClient {
    async fn token_review(
        &self,
        token: &str,
        audiences: &[String],
    ) -> Result<TokenReviewStatus, ApiError> {
        let review = TokenReview {
            spec: TokenReviewSpec {
                token: Some(token.to_string()),
                audiences: Some(audiences.to_vec()),
            },
            ..Default::default()
        };
        let api: Api<TokenReview> = Api::all(self.client.clone());
        let out = api.create(&PostParams::default(), &review).await?;
        Ok(out.status.unwrap_or_default())
    }

    async fn get_pod(&self, namespace: &str, name: &str) -> Result<Option<Pod>, ApiError> {
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        Ok(api.get_opt(name).await?)
    }

    async fn get_secret(&self, namespace: &str, name: &str) -> Result<Option<Secret>, ApiError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        Ok(api.get_opt(name).await?)
    }

    async fn create_secret(&self, namespace: &str, secret: &Secret) -> Result<Secret, ApiError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        Ok(api.create(&Self::post_params(), secret).await?)
    }

    async fn replace_secret(&self, namespace: &str, secret: &Secret) -> Result<Secret, ApiError> {
        let name = secret.metadata.name.clone().unwrap_or_default();
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        Ok(api.replace(&name, &Self::post_params(), secret).await?)
    }

    async fn get_webhook_config(
        &self,
        kind: WebhookKind,
        name: &str,
    ) -> Result<Option<Value>, ApiError> {
        use k8s_openapi::api::admissionregistration::v1::{
            MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
        };
        match kind {
            WebhookKind::Mutating => {
                let api: Api<MutatingWebhookConfiguration> = Api::all(self.client.clone());
                optional(api.get(name).await.map_err(ApiError::from))?
                    .map(|c| to_value(&c))
                    .transpose()
            }
            WebhookKind::Validating => {
                let api: Api<ValidatingWebhookConfiguration> = Api::all(self.client.clone());
                optional(api.get(name).await.map_err(ApiError::from))?
                    .map(|c| to_value(&c))
                    .transpose()
            }
        }
    }

    async fn patch_webhook_config(
        &self,
        kind: WebhookKind,
        name: &str,
        patch: &Value,
    ) -> Result<(), ApiError> {
        use k8s_openapi::api::admissionregistration::v1::{
            MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
        };
        let params = PatchParams {
            field_manager: Some(FIELD_MANAGER.to_string()),
            ..Default::default()
        };
        let patch = Patch::Strategic(patch);
        match kind {
            WebhookKind::Mutating => {
                let api: Api<MutatingWebhookConfiguration> = Api::all(self.client.clone());
                api.patch(name, &params, &patch).await?;
            }
            WebhookKind::Validating => {
                let api: Api<ValidatingWebhookConfiguration> = Api::all(self.client.clone());
                api.patch(name, &params, &patch).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CharterApi for KubeClient {
    async fn get(&self, namespace: &str, name: &str) -> Result<Option<Value>, ApiError> {
        self.charters(namespace)
            .get_opt(name)
            .await?
            .map(|o| to_value(&o))
            .transpose()
    }

    async fn list(&self) -> Result<Vec<Value>, ApiError> {
        let api: Api<DynamicObject> = Api::all_with(self.client.clone(), &self.charters);
        let list = api.list(&ListParams::default()).await?;
        list.items.iter().map(to_value).collect()
    }

    async fn create(&self, namespace: &str, object: &Value) -> Result<Value, ApiError> {
        let obj: DynamicObject = from_value(object)?;
        let out = self
            .charters(namespace)
            .create(&Self::post_params(), &obj)
            .await?;
        to_value(&out)
    }

    async fn replace(
        &self,
        namespace: &str,
        name: &str,
        object: &Value,
    ) -> Result<Value, ApiError> {
        let obj: DynamicObject = from_value(object)?;
        let out = self
            .charters(namespace)
            .replace(name, &Self::post_params(), &obj)
            .await?;
        to_value(&out)
    }

    async fn replace_status(
        &self,
        namespace: &str,
        name: &str,
        object: &Value,
    ) -> Result<Value, ApiError> {
        let obj: DynamicObject = from_value(object)?;
        let out = self
            .charters(namespace)
            .replace_status(name, &Self::post_params(), &obj)
            .await?;
        to_value(&out)
    }

    async fn delete(
        &self,
        namespace: &str,
        name: &str,
        resource_version: &str,
    ) -> Result<(), ApiError> {
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                resource_version: Some(resource_version.to_string()),
                uid: None,
            }),
            ..Default::default()
        };
        self.charters(namespace).delete(name, &params).await?;
        Ok(())
    }

    async fn list_revisions(
        &self,
        namespace: &str,
        label_selector: &str,
    ) -> Result<Vec<ControllerRevision>, ApiError> {
        let list = self
            .revisions(namespace)
            .list(&ListParams::default().labels(label_selector))
            .await?;
        Ok(list.items)
    }

    async fn get_revision(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ControllerRevision>, ApiError> {
        Ok(self.revisions(namespace).get_opt(name).await?)
    }

    async fn create_revision(
        &self,
        namespace: &str,
        revision: &ControllerRevision,
    ) -> Result<ControllerRevision, ApiError> {
        Ok(self
            .revisions(namespace)
            .create(&Self::post_params(), revision)
            .await?)
    }

    async fn delete_revision(&self, namespace: &str, name: &str) -> Result<(), ApiError> {
        match self
            .revisions(namespace)
            .delete(name, &DeleteParams::default())
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => match ApiError::from(e) {
                ApiError::NotFound => Ok(()),
                e => Err(e),
            },
        }
    }

    async fn get_config_map(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<ConfigMap>, ApiError> {
        Ok(self.config_maps(namespace).get_opt(name).await?)
    }

    async fn create_config_map(
        &self,
        namespace: &str,
        config_map: &ConfigMap,
    ) -> Result<ConfigMap, ApiError> {
        Ok(self
            .config_maps(namespace)
            .create(&Self::post_params(), config_map)
            .await?)
    }

    async fn replace_config_map(
        &self,
        namespace: &str,
        config_map: &ConfigMap,
    ) -> Result<ConfigMap, ApiError> {
        let name = config_map.metadata.name.clone().unwrap_or_default();
        Ok(self
            .config_maps(namespace)
            .replace(&name, &Self::post_params(), config_map)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::Status;

    fn status(code: u16, reason: &str) -> kube::Error {
        let mut s = Status::failure("boom", reason);
        s.code = code;
        kube::Error::Api(Box::new(s))
    }

    #[test]
    fn api_errors_map_by_code_and_reason() {
        assert_eq!(ApiError::from(status(404, "NotFound")), ApiError::NotFound);
        assert_eq!(
            ApiError::from(status(409, "AlreadyExists")),
            ApiError::AlreadyExists("boom".into())
        );
        assert_eq!(
            ApiError::from(status(409, "Conflict")),
            ApiError::Conflict("boom".into())
        );
        for code in [400, 403, 422] {
            assert_eq!(
                ApiError::from(status(code, "Invalid")),
                ApiError::Refused("boom".into())
            );
        }
        assert!(matches!(
            ApiError::from(status(500, "InternalError")),
            ApiError::Other(m) if m.contains("500")
        ));
        assert_eq!(optional::<u8>(Err(ApiError::NotFound)), Ok(None));
        assert_eq!(optional(Ok(1u8)), Ok(Some(1)));
        assert!(optional::<u8>(Err(ApiError::Other("x".into()))).is_err());
    }

    #[test]
    fn the_charter_resource_is_agentsc_io() {
        let ar = charter_resource();
        assert_eq!(ar.api_version, "agentsc.io/v1alpha1");
        assert_eq!(ar.kind, "Charter");
        assert_eq!(ar.plural, "charters");
    }
}
