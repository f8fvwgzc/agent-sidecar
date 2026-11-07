//! Console sign-in through an OIDC issuer (Tutela INTEGRATION §3 step 2, design §8.3): the code
//! flow against a fake Keycloak on loopback, every way it must refuse, and `att_` tokens next to it.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use common::{Env, Opts};
use embassy::config::{OidcConfig, OidcGroup, OidcUser, Role};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const TENANT: &str = "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c";
const CLIENT: &str = "embassy";
const SUB: &str = "4f8c2b1e-0000-4000-8000-000000000001";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An ES256 key of the issuer.
struct Signer(EcdsaKeyPair);

impl Signer {
    fn new() -> Self {
        Self(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap())
    }

    fn jwk(&self) -> Value {
        let point = self.0.public_key().as_ref();
        json!({"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig",
               "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65])})
    }

    fn token(&self, claims: &Value) -> String {
        let header = json!({"typ": "JWT", "alg": "ES256", "kid": "k1"});
        let signed = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(claims).unwrap())
        );
        let sig = self
            .0
            .sign(&SystemRandom::new(), signed.as_bytes())
            .unwrap();
        format!("{signed}.{}", B64.encode(sig.as_ref()))
    }
}

/// One code the issuer would redeem.
struct Grant {
    challenge: String,
    id_token: String,
}

#[derive(Clone)]
struct Fake {
    signer: Arc<Signer>,
    codes: Arc<Mutex<HashMap<String, Grant>>>,
}

async fn certs(State(f): State<Fake>) -> Json<Value> {
    Json(json!({"keys": [f.signer.jwk()]}))
}

/// The token endpoint: PKCE is checked, and a code works once.
async fn token(State(f): State<Fake>, Form(form): Form<HashMap<String, String>>) -> Response {
    let grant = form
        .get("code")
        .and_then(|c| f.codes.lock().unwrap().remove(c));
    let Some(grant) = grant else {
        return (StatusCode::BAD_REQUEST, "invalid_grant").into_response();
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if B64.encode(Sha256::digest(verifier.as_bytes())) != grant.challenge
        || form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || form.get("client_id").map(String::as_str) != Some(CLIENT)
        || form.get("client_secret").map(String::as_str) != Some("s3cret")
    {
        return (StatusCode::BAD_REQUEST, "invalid_grant").into_response();
    }
    Json(json!({"id_token": grant.id_token, "token_type": "Bearer"})).into_response()
}

struct Issuer {
    url: String,
    fake: Fake,
}

impl Issuer {
    async fn start() -> Issuer {
        let fake = Fake {
            signer: Arc::new(Signer::new()),
            codes: Arc::default(),
        };
        let app = Router::new()
            .route("/realms/dev/protocol/openid-connect/certs", get(certs))
            .route("/realms/dev/protocol/openid-connect/token", post(token))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        Issuer {
            url: format!("http://{addr}/realms/dev"),
            fake,
        }
    }

    /// Valid claims for `nonce`.
    fn claims(&self, nonce: &str) -> Value {
        let t = now();
        json!({"iss": self.url, "sub": SUB, "aud": CLIENT, "iat": t, "exp": t + 300,
               "nonce": nonce, "typ": "ID"})
    }

    fn config(&self, secret: &std::path::Path) -> OidcConfig {
        serde_json::from_value(json!({
            "issuer": self.url,
            "tenant": TENANT,
            "client_id": CLIENT,
            "client_secret_file": secret,
            "redirect_url": "http://127.0.0.1:1/api/v1/auth/oidc/callback",
            "dev_loopback": true,
            "algs": ["ES256"],
            "users": [OidcUser {
                sub: SUB.into(),
                name: "carla".into(),
                role: Role::Editor,
                namespaces: vec!["*".into()],
                payloads: false,
            }],
            "groups": [OidcGroup {
                group: "auditors".into(),
                role: Role::Viewer,
                namespaces: vec!["shop".into()],
                payloads: false,
            }, OidcGroup {
                group: "operators".into(),
                role: Role::Admin,
                namespaces: vec!["*".into()],
                payloads: false,
            }],
        }))
        .unwrap()
    }
}

struct Rig {
    env: Env,
    issuer: Issuer,
    browser: reqwest::Client,
    _dir: tempfile::TempDir,
}

/// One trip to the issuer and back.
struct Trip {
    state: String,
    nonce: String,
    challenge: String,
    cookie: String,
}

impl Rig {
    async fn start() -> Rig {
        Self::start_edited(|_| {}).await
    }

    /// [`Rig::start`] with `edit` applied to `auth.oidc`.
    async fn start_edited(edit: impl FnOnce(&mut OidcConfig)) -> Rig {
        let issuer = Issuer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let mut oidc = issuer.config(&secret);
        edit(&mut oidc);
        let env = Env::start_with(Opts {
            oidc: Some(oidc),
            ..Opts::default()
        })
        .await;
        let browser = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Rig {
            env,
            issuer,
            browser,
            _dir: dir,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.env.base)
    }

    async fn begin(&self) -> Trip {
        let r = self
            .browser
            .get(self.url("/auth/oidc/login"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303);
        let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        let location = url::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
        assert!(
            location.as_str().starts_with(&self.issuer.url),
            "{location}"
        );
        let q: HashMap<String, String> = location.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], CLIENT);
        assert_eq!(q["code_challenge_method"], "S256");
        Trip {
            state: q["state"].clone(),
            nonce: q["nonce"].clone(),
            challenge: q["code_challenge"].clone(),
            cookie: cookie.split(';').next().unwrap().to_string(),
        }
    }

    /// The issuer accepts: `id_token` will be redeemed for a code.
    fn issue(&self, trip: &Trip, id_token: String) -> String {
        let code = format!("code-{}", trip.state);
        self.issuer.fake.codes.lock().unwrap().insert(
            code.clone(),
            Grant {
                challenge: trip.challenge.clone(),
                id_token,
            },
        );
        code
    }

    async fn back(&self, trip: &Trip, code: &str, state: &str) -> reqwest::Response {
        self.browser
            .get(self.url(&format!("/auth/oidc/callback?code={code}&state={state}")))
            .header("Cookie", &trip.cookie)
            .send()
            .await
            .unwrap()
    }

    /// A whole sign-in with these claims; the session cookie.
    async fn sign_in(&self, edit: impl FnOnce(&mut Value)) -> Option<String> {
        let trip = self.begin().await;
        let mut claims = self.issuer.claims(&trip.nonce);
        edit(&mut claims);
        let code = self.issue(&trip, self.issuer.fake.signer.token(&claims));
        let r = self.back(&trip, &code, &trip.state).await;
        r.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|c| c.to_str().ok())
            .find(|c| c.starts_with("agentsc_session="))
            .map(|c| {
                assert!(
                    c.contains("HttpOnly") && c.contains("SameSite=Strict"),
                    "{c}"
                );
                // a person's session is short: an hour, not a token's 12
                assert!(c.contains("Max-Age=3600"), "{c}");
                c.split(';').next().unwrap().to_string()
            })
    }

    async fn whoami(&self, cookie: &str) -> (u16, Value) {
        let r = self
            .browser
            .get(self.url("/whoami"))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// The refused outcome: back to the sign-in screen, no session.
    async fn refused(&self, edit: impl FnOnce(&mut Value), code: &str) {
        let trip = self.begin().await;
        let mut claims = self.issuer.claims(&trip.nonce);
        edit(&mut claims);
        let issued = self.issue(&trip, self.issuer.fake.signer.token(&claims));
        let r = self.back(&trip, &issued, &trip.state).await;
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers()["location"], format!("/?signin={code}").as_str());
        assert!(
            !r.headers()
                .get_all("set-cookie")
                .iter()
                .any(|c| c.to_str().unwrap().starts_with("agentsc_session=")),
        );
    }
}

#[tokio::test]
async fn a_person_signs_in_and_the_session_is_the_usual_cookie() {
    let rig = Rig::start().await;
    let m: Value = rig
        .browser
        .get(rig.url("/auth/methods"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m, json!({"token": true, "oidc": true}));

    let cookie = rig.sign_in(|_| {}).await.expect("a session");
    let (status, me) = rig.whoami(&cookie).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["name"], "carla");
    assert_eq!(me["role"], "editor");

    // the sign-in is audited, by name
    let audit = std::fs::read_to_string(rig.env.store_dir.join(".audit.jsonl")).unwrap();
    assert!(
        audit.lines().any(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["action"] == "login" && v["actor"] == "carla"
        }),
        "{audit}"
    );

    // sign out: the issuer's session goes too
    let r = rig
        .browser
        .post(rig.url("/logout"))
        .header("Cookie", &cookie)
        .header("X-Agentsc-CSRF", "1")
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    let end = v["end_session_url"].as_str().unwrap();
    assert!(end.starts_with(&rig.issuer.url), "{end}");
    assert!(end.contains("/protocol/openid-connect/logout"), "{end}");
    rig.env.stop().await;
}

#[tokio::test]
async fn att_tokens_keep_working_next_to_it() {
    let rig = Rig::start().await;
    let r = rig.env.get("/whoami", "alice").await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = Env::send(
        rig.env
            .req("POST", "/api/v1/login", None)
            .body(json!({"token": rig.env.token("alice")}).to_string()),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text);
    rig.env.stop().await;
}

#[tokio::test]
async fn the_first_group_in_the_file_decides_and_roles_are_never_merged() {
    let rig = Rig::start().await;
    let groups = |g: Value| {
        move |c: &mut Value| {
            c["sub"] = json!("someone-else");
            c["groups"] = g;
        }
    };
    let cookie = rig
        .sign_in(groups(json!(["operators", "auditors"])))
        .await
        .unwrap();
    let (_, me) = rig.whoami(&cookie).await;
    // `auditors` comes first in the file: the viewer of one namespace, not an admin of all
    assert_eq!(me["role"], "viewer");
    assert_eq!(me["namespaces"], json!(["shop"]));
    assert_eq!(me["name"], "oidc:someone-else");

    let cookie = rig.sign_in(groups(json!(["operators"]))).await.unwrap();
    assert_eq!(rig.whoami(&cookie).await.1["role"], "admin");

    // a user entry comes before any group
    let cookie = rig
        .sign_in(|c| c["groups"] = json!(["operators"]))
        .await
        .unwrap();
    assert_eq!(rig.whoami(&cookie).await.1["name"], "carla");
    rig.env.stop().await;
}

#[tokio::test]
async fn every_bad_answer_is_refused() {
    let rig = Rig::start().await;
    // a person the configuration does not name
    rig.refused(|c| c["sub"] = json!("a-stranger"), "no_access")
        .await;
    // the ID token: another nonce, another audience, expired, another issuer
    rig.refused(|c| c["nonce"] = json!("replayed"), "failed")
        .await;
    rig.refused(|c| c["aud"] = json!("another-client"), "failed")
        .await;
    let long_ago = now() - 3600;
    rig.refused(
        |c| {
            c["iat"] = json!(long_ago);
            c["exp"] = json!(long_ago + 60);
        },
        "failed",
    )
    .await;
    rig.refused(
        |c| c["iss"] = json!("http://127.0.0.1:9/realms/other"),
        "failed",
    )
    .await;
    rig.env.stop().await;
}

/// Since Tutela v0.2.0 a failed request of `tutela-safenet` says only `the request failed`
/// (kind `Http`), and the reason is in its `source()` (MIGRATION-0.2.md, tutela#44). The refusal
/// walks the chain, so the `login_failed` record still says why.
#[tokio::test]
async fn an_unreachable_token_endpoint_is_audited_with_its_reason() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let rig = Rig::start_edited(|o| {
        o.token_endpoint = Some(format!("http://127.0.0.1:{port}/token"));
    })
    .await;
    rig.refused(|_| {}, "failed").await;
    let audit = std::fs::read_to_string(rig.env.store_dir.join(".audit.jsonl")).unwrap();
    let reason = audit
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|l| l["action"] == "login_failed")
        .filter_map(|l| l["reason"].as_str().map(str::to_string))
        .find(|r| r.contains("the token endpoint"))
        .expect("a login_failed record for the token endpoint");
    let (_, cause) = reason
        .split_once("the token endpoint: the request failed: ")
        .unwrap_or_else(|| panic!("no cause after the request failed: {reason:?}"));
    assert!(!cause.trim().is_empty(), "the reason is lost: {reason:?}");
    rig.env.stop().await;
}

#[tokio::test]
async fn a_forged_token_or_a_foreign_state_is_refused() {
    let rig = Rig::start().await;
    // signed with a key the issuer does not publish
    let trip = rig.begin().await;
    let forged = Signer::new().token(&rig.issuer.claims(&trip.nonce));
    let code = rig.issue(&trip, forged);
    let r = rig.back(&trip, &code, &trip.state).await;
    assert_eq!(r.headers()["location"], "/?signin=failed");

    // the state of another sign-in
    let trip = rig.begin().await;
    let token = rig
        .issuer
        .fake
        .signer
        .token(&rig.issuer.claims(&trip.nonce));
    let code = rig.issue(&trip, token);
    let r = rig.back(&trip, &code, "another-state").await;
    assert_eq!(r.headers()["location"], "/?signin=failed");

    // no state cookie at all
    let r = rig
        .browser
        .get(rig.url(&format!(
            "/auth/oidc/callback?code={code}&state={}",
            trip.state
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "/?signin=failed");

    rig.env.stop().await;
}

#[tokio::test]
async fn too_many_failures_stop_at_the_limiter() {
    let rig = Rig::start().await;
    for _ in 0..embassy::auth::LOGIN_FAILURES {
        rig.refused(|c| c["nonce"] = json!("wrong"), "failed").await;
    }
    let trip = rig.begin().await;
    let r = rig.back(&trip, "any", &trip.state).await;
    assert_eq!(r.headers()["location"], "/?signin=rate_limited");
    rig.env.stop().await;
}

#[tokio::test]
async fn leaving_the_configuration_ends_the_session() {
    let rig = Rig::start().await;
    let cookie = rig.sign_in(|_| {}).await.unwrap();
    assert_eq!(rig.whoami(&cookie).await.0, 200);

    let hub = rig.env.hub.clone();
    let mut next = (**hub.config.load()).clone();
    next.auth.oidc.as_mut().unwrap().users.clear();
    hub.auth.reload_key(&next).unwrap();
    hub.config.store(Arc::new(next));

    assert_eq!(rig.whoami(&cookie).await.0, 401);
    rig.env.stop().await;
}

#[tokio::test]
async fn a_person_is_a_user_principal_in_the_shadow_check() {
    let rig = Rig::start().await;
    let cookie = rig.sign_in(|_| {}).await.unwrap();
    let ident = rig
        .env
        .hub
        .auth
        .from_session(cookie.split_once('=').unwrap().1)
        .unwrap();
    let caller = ident.caller();
    assert_eq!(
        caller.principal,
        embassy::authz::user_principal(&rig.issuer.url, SUB)
    );
    assert_eq!(caller.role, Role::Editor);
    rig.env.stop().await;
}

#[tokio::test]
async fn without_auth_oidc_there_is_no_flow() {
    let env = Env::start().await;
    let r = env.get("/auth/methods", "alice").await;
    assert_eq!(
        serde_json::from_str::<Value>(&r.text).unwrap()["oidc"],
        false
    );
    let r = env.get("/auth/oidc/login", "alice").await;
    assert_eq!(r.status, 404, "{}", r.text);
    env.stop().await;
}

#[test]
fn the_configuration_is_checked() {
    use embassy::config::ControlPlaneConfig;
    let issuer = "https://kc.example.test/realms/acme";
    let good = json!({
        "issuer": issuer, "tenant": TENANT, "client_id": CLIENT,
        "redirect_url": "https://embassy.example.test/api/v1/auth/oidc/callback",
        "groups": [{"group": "ops", "role": "admin", "namespaces": ["*"]}],
    });
    let check = |edit: fn(&mut Value)| {
        let mut v = good.clone();
        edit(&mut v);
        let mut c = ControlPlaneConfig::default();
        c.auth.oidc = Some(serde_json::from_value(v).unwrap());
        c.validate("agentsc-system")
            .err()
            .unwrap_or_default()
            .join("; ")
    };
    assert_eq!(check(|_| {}), "");
    assert!(check(|v| v["tenant"] = json!("acme")).contains("auth.oidc.tenant"));
    assert!(
        check(|v| v["issuer"] = json!("http://kc.example.test/r")).contains("auth.oidc.issuer")
    );
    assert!(check(|v| v["algs"] = json!(["none"])).contains("auth.oidc.algs"));
    assert!(check(|v| v["redirect_url"] = json!("https://e.test/cb")).contains("must end in"));
    assert!(check(|v| v["groups"] = json!([])).contains("nobody could sign in"));
    assert!(check(|v| v["session_seconds"] = json!(60)).contains("session_seconds"));
    assert!(check(|v| v["session_seconds"] = json!(86400)).contains("session_seconds"));
    assert!(
        check(|v| v["users"] = json!([
            {"sub": "a", "name": "Not A Label", "role": "admin", "namespaces": ["*"]}
        ]))
        .contains("DNS-1123")
    );
    // the endpoints default to Keycloak's paths
    let o: OidcConfig = serde_json::from_value(good.clone()).unwrap();
    assert_eq!(
        o.token_endpoint(),
        format!("{issuer}/protocol/openid-connect/token")
    );
    assert_eq!(
        o.jwks_uri(),
        format!("{issuer}/protocol/openid-connect/certs")
    );
}
