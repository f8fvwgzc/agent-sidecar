//! The connected sidecar instances (design §7): one per open `Connect` stream, keyed by the
//! service of its certificate. `GET /services`, the graph, the version-skew and restart checks
//! and the pushes of charter and memory updates read it.
use std::collections::BTreeMap;
use std::sync::Mutex;

use attache_proto::ControlMessage;
use tokio::sync::mpsc;
use tonic::Status;

use crate::api::types::Instance;
use crate::store::ServiceKey;

/// The sending half of one instance's `ControlMessage` stream.
pub type Outbox = mpsc::Sender<Result<ControlMessage, Status>>;

/// One connected instance.
#[derive(Debug, Clone)]
pub struct Connected {
    /// What `GET /services` shows.
    pub info: Instance,
    /// `Hello.charter_schema_level` (0 from a sidecar that does not send it counts as 1).
    pub schema_level: u32,
    /// `Hello.app_port` (0 when not sent).
    pub app_port: u32,
    pub outbox: Outbox,
}

/// Every connected instance; see the module docs.
#[derive(Debug, Default)]
pub struct Registry {
    inner: Mutex<BTreeMap<ServiceKey, Vec<Connected>>>,
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<ServiceKey, Vec<Connected>>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn add(&self, key: ServiceKey, instance: Connected) {
        self.lock().entry(key).or_default().push(instance);
    }

    /// Remove one instance; returns it.
    pub fn remove(&self, key: &ServiceKey, instance_id: &str) -> Option<Connected> {
        let mut map = self.lock();
        let list = map.get_mut(key)?;
        let idx = list
            .iter()
            .position(|c| c.info.instance_id == instance_id)?;
        let removed = list.remove(idx);
        if list.is_empty() {
            map.remove(key);
        }
        Some(removed)
    }

    /// Change one instance; `None` when it is gone.
    pub fn update<T>(
        &self,
        key: &ServiceKey,
        instance_id: &str,
        f: impl FnOnce(&mut Connected) -> T,
    ) -> Option<T> {
        let mut map = self.lock();
        map.get_mut(key)?
            .iter_mut()
            .find(|c| c.info.instance_id == instance_id)
            .map(f)
    }

    /// The instances of a service, oldest connection first.
    pub fn instances(&self, key: &ServiceKey) -> Vec<Connected> {
        self.lock().get(key).cloned().unwrap_or_default()
    }

    /// Every service with a connected instance.
    pub fn services(&self) -> Vec<ServiceKey> {
        self.lock().keys().cloned().collect()
    }

    /// The `app_port` the instances of a service reported, if any.
    pub fn app_port(&self, key: &ServiceKey) -> Option<u16> {
        self.lock()
            .get(key)?
            .iter()
            .find_map(|c| u16::try_from(c.app_port).ok().filter(|p| *p != 0))
    }

    /// The outboxes of a service's instances.
    pub fn outboxes(&self, key: &ServiceKey) -> Vec<Outbox> {
        self.lock()
            .get(key)
            .map(|l| l.iter().map(|c| c.outbox.clone()).collect())
            .unwrap_or_default()
    }

    /// Every instance (all services), for a full resync.
    pub fn all(&self) -> Vec<(ServiceKey, Connected)> {
        self.lock()
            .iter()
            .flat_map(|(k, l)| l.iter().map(move |c| (k.clone(), c.clone())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(
        id: &str,
        level: u32,
        port: u32,
    ) -> (Connected, mpsc::Receiver<Result<ControlMessage, Status>>) {
        let (tx, rx) = mpsc::channel(1);
        (
            Connected {
                info: Instance {
                    instance_id: id.into(),
                    pod: format!("pod-{id}"),
                    sidecar_version: "0.2.0".into(),
                    connected_at: "2026-10-21T10:00:00.000Z".into(),
                    last_heartbeat: None,
                    runtime_ready: false,
                    acked_version: None,
                    ack_error: None,
                    cert_expires_in_s: None,
                    audit_dropped: 0,
                },
                schema_level: level,
                app_port: port,
                outbox: tx,
            },
            rx,
        )
    }

    #[test]
    fn instances_come_and_go() {
        let r = Registry::default();
        let key = ServiceKey::new("shop", "orders");
        let (a, _ra) = instance("a", 2, 0);
        let (b, _rb) = instance("b", 1, 8080);
        r.add(key.clone(), a);
        r.add(key.clone(), b);
        assert_eq!(r.instances(&key).len(), 2);
        assert_eq!(r.app_port(&key), Some(8080));
        assert_eq!(r.services(), std::slice::from_ref(&key));
        assert_eq!(r.outboxes(&key).len(), 2);
        assert_eq!(
            r.update(&key, "a", |c| {
                c.info.runtime_ready = true;
                c.info.pod.clone()
            }),
            Some("pod-a".to_string())
        );
        assert!(r.instances(&key)[0].info.runtime_ready);
        assert!(r.update(&key, "zz", |_| ()).is_none());
        assert!(r.remove(&key, "a").is_some());
        assert!(r.remove(&key, "a").is_none());
        assert_eq!(r.all().len(), 1);
        assert!(r.remove(&key, "b").is_some());
        assert!(r.services().is_empty());
    }
}
