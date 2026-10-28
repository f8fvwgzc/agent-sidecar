from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Empty(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class Usage(_message.Message):
    __slots__ = ("input_tokens", "output_tokens", "cost_usd")
    INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    COST_USD_FIELD_NUMBER: _ClassVar[int]
    input_tokens: int
    output_tokens: int
    cost_usd: float
    def __init__(self, input_tokens: _Optional[int] = ..., output_tokens: _Optional[int] = ..., cost_usd: _Optional[float] = ...) -> None: ...

class Step(_message.Message):
    __slots__ = ("kind", "name", "decision", "rule", "latency_ms", "summary")
    KIND_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    kind: str
    name: str
    decision: str
    rule: str
    latency_ms: int
    summary: str
    def __init__(self, kind: _Optional[str] = ..., name: _Optional[str] = ..., decision: _Optional[str] = ..., rule: _Optional[str] = ..., latency_ms: _Optional[int] = ..., summary: _Optional[str] = ...) -> None: ...

class InvokeAgentRequest(_message.Message):
    __slots__ = ("agent", "input", "context_json", "request_id", "traceparent", "caller_agent", "depth")
    AGENT_FIELD_NUMBER: _ClassVar[int]
    INPUT_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_JSON_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACEPARENT_FIELD_NUMBER: _ClassVar[int]
    CALLER_AGENT_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    agent: str
    input: str
    context_json: str
    request_id: str
    traceparent: str
    caller_agent: str
    depth: int
    def __init__(self, agent: _Optional[str] = ..., input: _Optional[str] = ..., context_json: _Optional[str] = ..., request_id: _Optional[str] = ..., traceparent: _Optional[str] = ..., caller_agent: _Optional[str] = ..., depth: _Optional[int] = ...) -> None: ...

class Question(_message.Message):
    __slots__ = ("question", "recommended")
    QUESTION_FIELD_NUMBER: _ClassVar[int]
    RECOMMENDED_FIELD_NUMBER: _ClassVar[int]
    question: str
    recommended: str
    def __init__(self, question: _Optional[str] = ..., recommended: _Optional[str] = ...) -> None: ...

class InvokeAgentResponse(_message.Message):
    __slots__ = ("status", "request_id", "trace_id", "agent", "output", "usage", "steps", "rule", "reason", "questions")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    RULE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    QUESTIONS_FIELD_NUMBER: _ClassVar[int]
    status: str
    request_id: str
    trace_id: str
    agent: str
    output: str
    usage: Usage
    steps: _containers.RepeatedCompositeFieldContainer[Step]
    rule: str
    reason: str
    questions: _containers.RepeatedCompositeFieldContainer[Question]
    def __init__(self, status: _Optional[str] = ..., request_id: _Optional[str] = ..., trace_id: _Optional[str] = ..., agent: _Optional[str] = ..., output: _Optional[str] = ..., usage: _Optional[_Union[Usage, _Mapping]] = ..., steps: _Optional[_Iterable[_Union[Step, _Mapping]]] = ..., rule: _Optional[str] = ..., reason: _Optional[str] = ..., questions: _Optional[_Iterable[_Union[Question, _Mapping]]] = ...) -> None: ...

class ServiceRequest(_message.Message):
    __slots__ = ("method", "path", "headers", "body", "request_id", "traceparent", "agent")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TRACEPARENT_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    method: str
    path: str
    headers: _containers.ScalarMap[str, str]
    body: bytes
    request_id: str
    traceparent: str
    agent: str
    def __init__(self, method: _Optional[str] = ..., path: _Optional[str] = ..., headers: _Optional[_Mapping[str, str]] = ..., body: _Optional[bytes] = ..., request_id: _Optional[str] = ..., traceparent: _Optional[str] = ..., agent: _Optional[str] = ...) -> None: ...

class ServiceResponse(_message.Message):
    __slots__ = ("status", "headers", "body")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    status: int
    headers: _containers.ScalarMap[str, str]
    body: bytes
    def __init__(self, status: _Optional[int] = ..., headers: _Optional[_Mapping[str, str]] = ..., body: _Optional[bytes] = ...) -> None: ...
