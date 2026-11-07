//! embassy as the issuer of its agents' own tokens (docs/adr/0005-agents-in-tutelad.md).
//!
//! An agent token is a Tutela access token (CONTRACTS.md 4.1, 4.2): `typ: at+jwt`, ES256, `kid`
//! the RFC 7638 thumbprint, `sub` the agent's principal in `tutelad`, `aud` `tutelad`'s own
//! audience, `tid` the app's tenant, `epoch` the agent's epoch as `tutelad` last said it, and a
//! life of 60 s. `tutelad` takes it as the `actor_token` of a delegated token: its trust file
//! lists `tutela.agent_tokens.issuer` with the JWKS at `/.well-known/agent-jwks.json` and the
//! tenant. embassy signs one only for an agent the registry holds as active, not quarantined, and
//! registered in `tutelad`.
use std::path::Path;

use anyhow::Context;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::AgentTokensConfig;

/// The life of an agent token: it is spent on one exchange.
pub const AGENT_TOKEN_SECS: u64 = 60;

/// The key that signs agent tokens.
pub struct Signer {
    key: EcdsaKeyPair,
    kid: String,
    jwk: Value,
    issuer: String,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// What an agent token says (the claims embassy chooses).
#[derive(Debug, Clone)]
pub struct AgentClaims<'a> {
    /// `agent:agt_<uuidv7>`, the principal `tutelad` made.
    pub agent: &'a str,
    /// `ten_<uuidv7>`.
    pub tenant: &'a str,
    /// `tutelad`'s own audience.
    pub audience: &'a str,
    /// The app's client id.
    pub azp: &'a str,
    /// The agent's epoch in `tutelad`.
    pub epoch: u64,
}

impl Signer {
    pub fn load(config: &AgentTokensConfig) -> anyhow::Result<Signer> {
        let text = std::fs::read_to_string(&config.key_file)
            .with_context(|| format!("read {}", config.key_file.display()))?;
        Self::from_pem(&config.issuer, &text, &config.key_file)
    }

    /// From a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) of a P-256 key.
    pub fn from_pem(issuer: &str, pem: &str, from: &Path) -> anyhow::Result<Signer> {
        let body: String = pem
            .lines()
            .map(str::trim)
            .skip_while(|l| *l != "-----BEGIN PRIVATE KEY-----")
            .skip(1)
            .take_while(|l| *l != "-----END PRIVATE KEY-----")
            .collect();
        anyhow::ensure!(
            !body.is_empty(),
            "{} is not a PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)",
            from.display()
        );
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .with_context(|| format!("{} is not base64 inside", from.display()))?;
        Self::from_pkcs8(issuer, &der)
            .with_context(|| format!("{} is not a P-256 key", from.display()))
    }

    pub fn from_pkcs8(issuer: &str, der: &[u8]) -> anyhow::Result<Signer> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
            .map_err(|e| anyhow::anyhow!("the key is refused: {e}"))?;
        let point = key.public_key().as_ref();
        anyhow::ensure!(
            point.len() == 65 && point[0] == 4,
            "not an uncompressed P-256 point"
        );
        let (x, y) = (B64.encode(&point[1..33]), B64.encode(&point[33..65]));
        // RFC 7638: the required members, sorted, no whitespace
        let thumb = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = B64.encode(Sha256::digest(thumb.as_bytes()));
        let jwk = json!({"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid,
                         "alg": "ES256", "use": "sig"});
        Ok(Signer {
            key,
            kid,
            jwk,
            issuer: issuer.to_string(),
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// `GET /.well-known/agent-jwks.json`.
    pub fn jwks(&self) -> Value {
        json!({ "keys": [self.jwk] })
    }

    /// A signed agent token for `c`, valid from `now` (Unix seconds) for [`AGENT_TOKEN_SECS`].
    pub fn sign(&self, c: &AgentClaims<'_>, now: u64) -> anyhow::Result<String> {
        let header = json!({"typ": "at+jwt", "alg": "ES256", "kid": self.kid});
        let jti = uuid::Uuid::now_v7().to_string();
        let claims = json!({
            "iss": self.issuer,
            "sub": c.agent,
            "aud": c.audience,
            "azp": c.azp,
            "iat": now,
            "nbf": now,
            "exp": now + AGENT_TOKEN_SECS,
            "jti": jti,
            "tid": c.tenant,
            "epoch": c.epoch,
            "rev": 0,
        });
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| anyhow::anyhow!("signing an agent token failed"))?;
        Ok(format!("{input}.{}", B64.encode(sig.as_ref())))
    }
}

/// A new P-256 key as PKCS#8 PEM, for `tutela.agent_tokens.key_file` (tests, a first set-up).
pub fn generate_pem() -> anyhow::Result<String> {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("generating a P-256 key failed"))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(doc.as_ref());
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    #[test]
    fn a_token_verifies_against_the_jwks_and_says_what_tutela_needs() {
        let pem = generate_pem().unwrap();
        let s = Signer::from_pem("https://embassy.example.test", &pem, Path::new("k")).unwrap();
        let t = s
            .sign(
                &AgentClaims {
                    agent: "agent:agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102",
                    tenant: "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c",
                    audience: "tutela-authz",
                    azp: "app_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2d",
                    epoch: 3,
                },
                1_800_000_000,
            )
            .unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        let header: Value = serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "at+jwt");
        assert_eq!(header["kid"], s.kid());
        let claims: Value = serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["epoch"], 3);
        assert_eq!(claims["exp"], 1_800_000_000 + AGENT_TOKEN_SECS);
        assert!(claims.get("sid").is_none() && claims.get("act").is_none());
        let jwk = &s.jwks()["keys"][0];
        let mut point = vec![4u8];
        point.extend(B64.decode(jwk["x"].as_str().unwrap()).unwrap());
        point.extend(B64.decode(jwk["y"].as_str().unwrap()).unwrap());
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &B64.decode(parts[2]).unwrap(),
            )
            .unwrap();
        assert_eq!(s.kid().len(), 43);
        assert!(Signer::from_pem("https://e.test", "not a key", Path::new("k")).is_err());
    }
}
