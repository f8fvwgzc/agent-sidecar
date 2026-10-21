//! `<state-dir>` (design §6.1, §6.3): the workload key (0600), certificate and CA, the last charter
//! and memory the control plane sent, and the sidecar's own learned notes. Every file is written
//! atomically (a temporary file, then a rename).
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::loaded::Memory;

pub const KEY_FILE: &str = "tls.key";
pub const CERT_FILE: &str = "tls.crt";
pub const CA_FILE: &str = "ca.crt";
pub const CHARTER_FILE: &str = "charter.yaml";
pub const CHARTER_META_FILE: &str = "charter.meta.json";
pub const MEMORY_FILE: &str = "memory.json";

/// Write `bytes` to `path` atomically, with `mode` (Unix permissions) on the new file.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".into());
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The epoch and version of the persisted charter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CharterMeta {
    pub epoch: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct StateDir {
    pub dir: PathBuf,
}

impl StateDir {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// `tls.key` (0600), `tls.crt`, `ca.crt`.
    pub fn save_tls(&self, key_pem: &str, cert_pem: &str, ca_pem: &str) -> std::io::Result<()> {
        write_atomic(&self.path(KEY_FILE), key_pem.as_bytes(), 0o600)?;
        write_atomic(&self.path(CERT_FILE), cert_pem.as_bytes(), 0o644)?;
        write_atomic(&self.path(CA_FILE), ca_pem.as_bytes(), 0o644)
    }

    /// `(ca, cert, key)` PEMs, when all three exist.
    pub fn load_tls(&self) -> Option<(String, String, String)> {
        let read = |n: &str| std::fs::read_to_string(self.path(n)).ok();
        Some((read(CA_FILE)?, read(CERT_FILE)?, read(KEY_FILE)?))
    }

    pub fn ca_pem(&self) -> Option<String> {
        std::fs::read_to_string(self.path(CA_FILE)).ok()
    }

    pub fn save_charter(&self, yaml: &str, meta: &CharterMeta) -> std::io::Result<()> {
        write_atomic(&self.path(CHARTER_FILE), yaml.as_bytes(), 0o644)?;
        let meta = serde_json::to_vec(meta).map_err(std::io::Error::other)?;
        write_atomic(&self.path(CHARTER_META_FILE), &meta, 0o644)
    }

    pub fn load_charter(&self) -> Option<(String, CharterMeta)> {
        let yaml = std::fs::read_to_string(self.path(CHARTER_FILE)).ok()?;
        let meta = std::fs::read(self.path(CHARTER_META_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())?;
        Some((yaml, meta))
    }

    pub fn save_memory(&self, memory: &Memory) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(memory).map_err(std::io::Error::other)?;
        write_atomic(&self.path(MEMORY_FILE), &bytes, 0o600)
    }

    pub fn load_memory(&self) -> Option<Memory> {
        std::fs::read(self.path(MEMORY_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_and_the_key_is_private() {
        let tmp = tempfile::tempdir().unwrap();
        let s = StateDir::new(tmp.path().join("state"));
        assert!(s.load_tls().is_none() && s.load_charter().is_none() && s.load_memory().is_none());
        s.save_tls("KEY", "CERT", "CA").unwrap();
        assert_eq!(
            s.load_tls(),
            Some(("CA".to_string(), "CERT".to_string(), "KEY".to_string()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(tmp.path().join("state/tls.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let meta = CharterMeta {
            epoch: "e1".into(),
            version: "3".into(),
        };
        s.save_charter("kind: Charter\n", &meta).unwrap();
        assert_eq!(s.load_charter(), Some(("kind: Charter\n".into(), meta)));
        let mut m = Memory {
            version: "2".into(),
            ..Default::default()
        };
        m.agents.insert("a".into(), vec![]);
        s.save_memory(&m).unwrap();
        assert_eq!(s.load_memory(), Some(m));
        // no temporary files are left behind
        let names: Vec<String> = std::fs::read_dir(tmp.path().join("state"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
    }
}
