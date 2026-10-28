from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SidecarMessage(_message.Message):
    __slots__ = ("hello", "heartbeat", "audit", "ack", "proposal", "span_start", "approval_request")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_FIELD_NUMBER: _ClassVar[int]
    ACK_FIELD_NUMBER: _ClassVar[int]
    PROPOSAL_FIELD_NUMBER: _ClassVar[int]
    SPAN_START_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_FIELD_NUMBER: _ClassVar[int]
    hello: Hello
    heartbeat: Heartbeat
    audit: AuditBatch
    ack: ConfigAck
    proposal: LearningProposal
    span_start: SpanStart
    approval_request: ApprovalRequest
    def __init__(self, hello: _Optional[_Union[Hello, _Mapping]] = ..., heartbeat: _Optional[_Union[Heartbeat, _Mapping]] = ..., audit: _Optional[_Union[AuditBatch, _Mapping]] = ..., ack: _Optional[_Union[ConfigAck, _Mapping]] = ..., proposal: _Optional[_Union[LearningProposal, _Mapping]] = ..., span_start: _Optional[_Union[SpanStart, _Mapping]] = ..., approval_request: _Optional[_Union[ApprovalRequest, _Mapping]] = ...) -> None: ...

class ApprovalRequest(_message.Message):
    __slots__ = ("id", "agent", "tool", "request_id", "trace_id", "args_sha256", "timeout_s", "requested_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    ARGS_SHA256_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_S_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    agent: str
    tool: str
    request_id: str
    trace_id: str
    args_sha256: str
    timeout_s: int
    requested_at: str
    def __init__(self, id: _Optional[str] = ..., agent: _Optional[str] = ..., tool: _Optional[str] = ..., request_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., args_sha256: _Optional[str] = ..., timeout_s: _Optional[int] = ..., requested_at: _Optional[str] = ...) -> None: ...

class Hello(_message.Message):
    __slots__ = ("service", "namespace", "pod", "sidecar_version", "charter_epoch", "charter_version", "charter_yaml", "app_port", "mesh_port", "charter_schema_level", "memory_version")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    POD_FIELD_NUMBER: _ClassVar[int]
    SIDECAR_VERSION_FIELD_NUMBER: _ClassVar[int]
    CHARTER_EPOCH_FIELD_NUMBER: _ClassVar[int]
    CHARTER_VERSION_FIELD_NUMBER: _ClassVar[int]
    CHARTER_YAML_FIELD_NUMBER: _ClassVar[int]
    APP_PORT_FIELD_NUMBER: _ClassVar[int]
    MESH_PORT_FIELD_NUMBER: _ClassVar[int]
    CHARTER_SCHEMA_LEVEL_FIELD_NUMBER: _ClassVar[int]
    MEMORY_VERSION_FIELD_NUMBER: _ClassVar[int]
    service: str
    namespace: str
    pod: str
    sidecar_version: str
    charter_epoch: str
    charter_version: str
    charter_yaml: str
    app_port: int
    mesh_port: int
    charter_schema_level: int
    memory_version: str
    def __init__(self, service: _Optional[str] = ..., namespace: _Optional[str] = ..., pod: _Optional[str] = ..., sidecar_version: _Optional[str] = ..., charter_epoch: _Optional[str] = ..., charter_version: _Optional[str] = ..., charter_yaml: _Optional[str] = ..., app_port: _Optional[int] = ..., mesh_port: _Optional[int] = ..., charter_schema_level: _Optional[int] = ..., memory_version: _Optional[str] = ...) -> None: ...

class Heartbeat(_message.Message):
    __slots__ = ("seq", "runtime_ready", "charter_version", "audit_dropped", "cert_expires_in_s")
    SEQ_FIELD_NUMBER: _ClassVar[int]
    RUNTIME_READY_FIELD_NUMBER: _ClassVar[int]
    CHARTER_VERSION_FIELD_NUMBER: _ClassVar[int]
    AUDIT_DROPPED_FIELD_NUMBER: _ClassVar[int]
    CERT_EXPIRES_IN_S_FIELD_NUMBER: _ClassVar[int]
    seq: int
    runtime_ready: bool
    charter_version: str
    audit_dropped: int
    cert_expires_in_s: int
    def __init__(self, seq: _Optional[int] = ..., runtime_ready: _Optional[bool] = ..., charter_version: _Optional[str] = ..., audit_dropped: _Optional[int] = ..., cert_expires_in_s: _Optional[int] = ...) -> None: ...

class AuditBatch(_message.Message):
    __slots__ = ("records_json",)
    RECORDS_JSON_FIELD_NUMBER: _ClassVar[int]
    records_json: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, records_json: _Optional[_Iterable[str]] = ...) -> None: ...

class ConfigAck(_message.Message):
    __slots__ = ("epoch", "version", "applied", "error", "kind")
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    APPLIED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    epoch: str
    version: str
    applied: bool
    error: str
    kind: str
    def __init__(self, epoch: _Optional[str] = ..., version: _Optional[str] = ..., applied: _Optional[bool] = ..., error: _Optional[str] = ..., kind: _Optional[str] = ...) -> None: ...

class SpanStart(_message.Message):
    __slots__ = ("request_id", "trace_id", "span_id", "parent_span_id", "kind", "agent", "caller", "caller_agent", "callee", "direction", "ts")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    PARENT_SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    CALLER_FIELD_NUMBER: _ClassVar[int]
    CALLER_AGENT_FIELD_NUMBER: _ClassVar[int]
    CALLEE_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    TS_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    trace_id: str
    span_id: str
    parent_span_id: str
    kind: str
    agent: str
    caller: str
    caller_agent: str
    callee: str
    direction: str
    ts: str
    def __init__(self, request_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., span_id: _Optional[str] = ..., parent_span_id: _Optional[str] = ..., kind: _Optional[str] = ..., agent: _Optional[str] = ..., caller: _Optional[str] = ..., caller_agent: _Optional[str] = ..., callee: _Optional[str] = ..., direction: _Optional[str] = ..., ts: _Optional[str] = ...) -> None: ...

class LearningProposal(_message.Message):
    __slots__ = ("dedup_key", "agent", "note", "rationale", "request_id", "trace_id", "auto")
    DEDUP_KEY_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    AUTO_FIELD_NUMBER: _ClassVar[int]
    dedup_key: str
    agent: str
    note: str
    rationale: str
    request_id: str
    trace_id: str
    auto: bool
    def __init__(self, dedup_key: _Optional[str] = ..., agent: _Optional[str] = ..., note: _Optional[str] = ..., rationale: _Optional[str] = ..., request_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., auto: _Optional[bool] = ...) -> None: ...

class ControlMessage(_message.Message):
    __slots__ = ("charter", "memory", "agent_ids", "quarantine", "approval_decision")
    CHARTER_FIELD_NUMBER: _ClassVar[int]
    MEMORY_FIELD_NUMBER: _ClassVar[int]
    AGENT_IDS_FIELD_NUMBER: _ClassVar[int]
    QUARANTINE_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_DECISION_FIELD_NUMBER: _ClassVar[int]
    charter: CharterUpdate
    memory: MemoryUpdate
    agent_ids: AgentIds
    quarantine: Quarantine
    approval_decision: ApprovalDecision
    def __init__(self, charter: _Optional[_Union[CharterUpdate, _Mapping]] = ..., memory: _Optional[_Union[MemoryUpdate, _Mapping]] = ..., agent_ids: _Optional[_Union[AgentIds, _Mapping]] = ..., quarantine: _Optional[_Union[Quarantine, _Mapping]] = ..., approval_decision: _Optional[_Union[ApprovalDecision, _Mapping]] = ...) -> None: ...

class ApprovalDecision(_message.Message):
    __slots__ = ("id", "decision", "decided_by", "reason")
    ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    DECIDED_BY_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    id: str
    decision: str
    decided_by: str
    reason: str
    def __init__(self, id: _Optional[str] = ..., decision: _Optional[str] = ..., decided_by: _Optional[str] = ..., reason: _Optional[str] = ...) -> None: ...

class Quarantine(_message.Message):
    __slots__ = ("agents",)
    class AgentsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    agents: _containers.ScalarMap[str, str]
    def __init__(self, agents: _Optional[_Mapping[str, str]] = ...) -> None: ...

class AgentIds(_message.Message):
    __slots__ = ("ids",)
    class IdsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    IDS_FIELD_NUMBER: _ClassVar[int]
    ids: _containers.ScalarMap[str, str]
    def __init__(self, ids: _Optional[_Mapping[str, str]] = ...) -> None: ...

class CharterUpdate(_message.Message):
    __slots__ = ("epoch", "version", "charter_yaml")
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    CHARTER_YAML_FIELD_NUMBER: _ClassVar[int]
    epoch: str
    version: str
    charter_yaml: str
    def __init__(self, epoch: _Optional[str] = ..., version: _Optional[str] = ..., charter_yaml: _Optional[str] = ...) -> None: ...

class Note(_message.Message):
    __slots__ = ("id", "text", "source", "request_id", "trace_id", "approved_by", "ts", "expires_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    APPROVED_BY_FIELD_NUMBER: _ClassVar[int]
    TS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    text: str
    source: str
    request_id: str
    trace_id: str
    approved_by: str
    ts: str
    expires_at: str
    def __init__(self, id: _Optional[str] = ..., text: _Optional[str] = ..., source: _Optional[str] = ..., request_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., approved_by: _Optional[str] = ..., ts: _Optional[str] = ..., expires_at: _Optional[str] = ...) -> None: ...

class MemoryUpdate(_message.Message):
    __slots__ = ("version", "agents")
    class AgentsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: NoteList
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[NoteList, _Mapping]] = ...) -> None: ...
    VERSION_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    version: str
    agents: _containers.MessageMap[str, NoteList]
    def __init__(self, version: _Optional[str] = ..., agents: _Optional[_Mapping[str, NoteList]] = ...) -> None: ...

class NoteList(_message.Message):
    __slots__ = ("notes",)
    NOTES_FIELD_NUMBER: _ClassVar[int]
    notes: _containers.RepeatedCompositeFieldContainer[Note]
    def __init__(self, notes: _Optional[_Iterable[_Union[Note, _Mapping]]] = ...) -> None: ...

class CertificateRequest(_message.Message):
    __slots__ = ("csr_pem", "kubernetes_token", "join_token", "namespace", "service")
    CSR_PEM_FIELD_NUMBER: _ClassVar[int]
    KUBERNETES_TOKEN_FIELD_NUMBER: _ClassVar[int]
    JOIN_TOKEN_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    csr_pem: str
    kubernetes_token: str
    join_token: str
    namespace: str
    service: str
    def __init__(self, csr_pem: _Optional[str] = ..., kubernetes_token: _Optional[str] = ..., join_token: _Optional[str] = ..., namespace: _Optional[str] = ..., service: _Optional[str] = ...) -> None: ...

class CertificateResponse(_message.Message):
    __slots__ = ("cert_pem", "ca_pem", "expires_at")
    CERT_PEM_FIELD_NUMBER: _ClassVar[int]
    CA_PEM_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    cert_pem: str
    ca_pem: str
    expires_at: str
    def __init__(self, cert_pem: _Optional[str] = ..., ca_pem: _Optional[str] = ..., expires_at: _Optional[str] = ...) -> None: ...
