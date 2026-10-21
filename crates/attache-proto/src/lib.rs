//! Generated from `proto/attache/v1alpha1/*.proto`. See CONTRACT.md §4.
//!
//! One package, one module: the app, mesh and runtime protocols (`app.proto`, `mesh.proto`,
//! `runtime.proto`) and the control-plane protocol (`controlplane.proto`: `ControlPlane.Connect`
//! and `CertificateAuthority.IssueCertificate`) are all re-exported at the crate root.
//!
//! The control-plane clients have no `connect(endpoint)` constructor (it would collide with the
//! `Connect` RPC): build them with `ControlPlaneClient::new(channel)` /
//! `CertificateAuthorityClient::new(channel)`.
pub mod v1alpha1 {
    tonic::include_proto!("attache.v1alpha1");
    include!(concat!(
        env!("OUT_DIR"),
        "/controlplane/attache.v1alpha1.rs"
    ));
}
pub use v1alpha1::*;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn control_plane_messages_round_trip() {
        let hello = SidecarMessage {
            msg: Some(sidecar_message::Msg::Hello(Hello {
                service: "orders".into(),
                namespace: "shop".into(),
                pod: "orders-0".into(),
                charter_schema_level: 2,
                app_port: 8080,
                mesh_port: 50002,
                ..Default::default()
            })),
        };
        let back = SidecarMessage::decode(hello.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, hello);

        let mut agents = std::collections::HashMap::new();
        agents.insert(
            "support".to_string(),
            NoteList {
                notes: vec![Note {
                    id: "n1".into(),
                    text: "Look up the order first.".into(),
                    source: "review".into(),
                    ..Default::default()
                }],
            },
        );
        let update = ControlMessage {
            msg: Some(control_message::Msg::Memory(MemoryUpdate {
                version: "3".into(),
                agents,
            })),
        };
        let back = ControlMessage::decode(update.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, update);
    }

    #[test]
    fn certificate_messages_round_trip() {
        let req = CertificateRequest {
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----".into(),
            kubernetes_token: "t".into(),
            join_token: String::new(),
            namespace: "shop".into(),
            service: "orders".into(),
        };
        let back = CertificateRequest::decode(req.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn lesson_messages_use_the_design_field_numbers() {
        // LessonRequest {ToolContext ctx = 1; string note = 2; string rationale = 3; string run_request_id = 4;}
        let req = LessonRequest {
            ctx: Some(ToolContext {
                agent: "a".into(),
                ..Default::default()
            }),
            note: "n".into(),
            rationale: "r".into(),
            run_request_id: "q".into(),
        };
        assert_eq!(
            req.encode_to_vec(),
            [
                0x0a, 3, 0x22, 1, b'a', // ctx = 1 { agent = 4 }
                0x12, 1, b'n', // note = 2
                0x1a, 1, b'r', // rationale = 3
                0x22, 1, b'q', // run_request_id = 4
            ]
        );
        // LessonResponse {string decision = 1; string rule = 2; string reason = 3;}
        let resp = LessonResponse {
            decision: "a".into(),
            rule: "b".into(),
            reason: "c".into(),
        };
        assert_eq!(
            resp.encode_to_vec(),
            [0x0a, 1, b'a', 0x12, 1, b'b', 0x1a, 1, b'c']
        );
    }
}
