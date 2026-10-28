from agentsc.v1alpha1 import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ExecuteRequest(_message.Message):
    __slots__ = ("request_id", "trace_id", "span_id", "agent_spec_json", "input", "context_json", "caller", "caller_agent", "depth")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_SPEC_JSON_FIELD_NUMBER: _ClassVar[int]
    INPUT_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_JSON_FIELD_NUMBER: _ClassVar[int]
    CALLER_FIELD_NUMBER: _ClassVar[int]
    CALLER_AGENT_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    trace_id: str
    span_id: str
    agent_spec_json: str
    input: str
    context_json: str
    caller: str
    caller_agent: str
    depth: int
    def __init__(self, request_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., span_id: _Optional[str] = ..., agent_spec_json: _Optional[str] = ..., input: _Optional[str] = ..., context_json: _Optional[str] = ..., caller: _Optional[str] = ..., caller_agent: _Optional[str] = ..., depth: _Optional[int] = ...) -> None: ...

class ExecuteResponse(_message.Message):
    __slots__ = ("status", "output", "usage", "steps", "rule", "reason", "questions")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    QUESTIONS_FIELD_NUMBER: _ClassVar[int]
    status: str
    output: str
    usage: _common_pb2.Usage
    steps: _containers.RepeatedCompositeFieldContainer[_common_pb2.Step]
    rule: str
    reason: str
    questions: _containers.RepeatedCompositeFieldContainer[_common_pb2.Question]
    def __init__(self, status: _Optional[str] = ..., output: _Optional[str] = ..., usage: _Optional[_Union[_common_pb2.Usage, _Mapping]] = ..., steps: _Optional[_Iterable[_Union[_common_pb2.Step, _Mapping]]] = ..., rule: _Optional[str] = ..., reason: _Optional[str] = ..., questions: _Optional[_Iterable[_Union[_common_pb2.Question, _Mapping]]] = ...) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("ok", "model_provider", "version")
    OK_FIELD_NUMBER: _ClassVar[int]
    MODEL_PROVIDER_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ok: bool
    model_provider: str
    version: str
    def __init__(self, ok: _Optional[bool] = ..., model_provider: _Optional[str] = ..., version: _Optional[str] = ...) -> None: ...

class ToolContext(_message.Message):
    __slots__ = ("request_id", "trace_id", "span_id", "agent", "tool", "depth")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    SPAN_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    trace_id: str
    span_id: str
    agent: str
    tool: str
    depth: int
    def __init__(self, request_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., span_id: _Optional[str] = ..., agent: _Optional[str] = ..., tool: _Optional[str] = ..., depth: _Optional[int] = ...) -> None: ...

class ToolServiceRequest(_message.Message):
    __slots__ = ("ctx", "service", "method", "path", "headers", "body")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CTX_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    ctx: ToolContext
    service: str
    method: str
    path: str
    headers: _containers.ScalarMap[str, str]
    body: bytes
    def __init__(self, ctx: _Optional[_Union[ToolContext, _Mapping]] = ..., service: _Optional[str] = ..., method: _Optional[str] = ..., path: _Optional[str] = ..., headers: _Optional[_Mapping[str, str]] = ..., body: _Optional[bytes] = ...) -> None: ...

class ToolAgentRequest(_message.Message):
    __slots__ = ("ctx", "target_service", "target_agent", "input")
    CTX_FIELD_NUMBER: _ClassVar[int]
    TARGET_SERVICE_FIELD_NUMBER: _ClassVar[int]
    TARGET_AGENT_FIELD_NUMBER: _ClassVar[int]
    INPUT_FIELD_NUMBER: _ClassVar[int]
    ctx: ToolContext
    target_service: str
    target_agent: str
    input: str
    def __init__(self, ctx: _Optional[_Union[ToolContext, _Mapping]] = ..., target_service: _Optional[str] = ..., target_agent: _Optional[str] = ..., input: _Optional[str] = ...) -> None: ...

class ToolHttpRequest(_message.Message):
    __slots__ = ("ctx", "method", "url", "headers", "body")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CTX_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    ctx: ToolContext
    method: str
    url: str
    headers: _containers.ScalarMap[str, str]
    body: bytes
    def __init__(self, ctx: _Optional[_Union[ToolContext, _Mapping]] = ..., method: _Optional[str] = ..., url: _Optional[str] = ..., headers: _Optional[_Mapping[str, str]] = ..., body: _Optional[bytes] = ...) -> None: ...

class AuditEvent(_message.Message):
    __slots__ = ("json",)
    JSON_FIELD_NUMBER: _ClassVar[int]
    json: str
    def __init__(self, json: _Optional[str] = ...) -> None: ...

class LessonRequest(_message.Message):
    __slots__ = ("ctx", "note", "rationale", "run_request_id")
    CTX_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_FIELD_NUMBER: _ClassVar[int]
    RUN_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    ctx: ToolContext
    note: str
    rationale: str
    run_request_id: str
    def __init__(self, ctx: _Optional[_Union[ToolContext, _Mapping]] = ..., note: _Optional[str] = ..., rationale: _Optional[str] = ..., run_request_id: _Optional[str] = ...) -> None: ...

class LessonResponse(_message.Message):
    __slots__ = ("decision", "rule", "reason")
    DECISION_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    decision: str
    rule: str
    reason: str
    def __init__(self, decision: _Optional[str] = ..., rule: _Optional[str] = ..., reason: _Optional[str] = ...) -> None: ...
