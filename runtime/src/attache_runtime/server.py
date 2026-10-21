"""gRPC server implementing Runtime (CONTRACT.md §4.3)."""

from __future__ import annotations

import logging
import sys
import time

import grpc
from pydantic import ValidationError

from . import __version__
from .agent import run_agent
from .models import anthropic_available, model_for
from .pb.attache.v1alpha1 import common_pb2, runtime_pb2, runtime_pb2_grpc
from .sidecar import GrpcSidecar
from .spec import AgentSpec
from .tools import CallContext

log = logging.getLogger("attache-runtime")


class RuntimeServicer(runtime_pb2_grpc.RuntimeServicer):
    def __init__(self, sidecar: GrpcSidecar) -> None:
        self._sidecar = sidecar

    async def Health(self, request, context):
        provider = "anthropic" if anthropic_available() else "mock"
        return runtime_pb2.HealthResponse(ok=True, model_provider=provider, version=__version__)

    async def Execute(self, request, context):
        try:
            spec = AgentSpec.model_validate_json(request.agent_spec_json)
        except ValidationError as e:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"agent_spec_json: {e}")
        # The sidecar sends what is left of its caller's deadline; every tool call fits inside it.
        remaining = context.time_remaining()
        deadline = time.monotonic() + remaining if remaining is not None else None
        ctx = CallContext(request.request_id, request.trace_id, request.span_id, spec.name, request.depth, deadline)
        model = model_for(spec.model)
        log.info(
            "execute agent=%s model=%s provider=%s request=%s",
            spec.name,
            model.name,
            model.provider,
            request.request_id,
        )
        result = await run_agent(
            spec, request.input, request.context_json, ctx, model, self._sidecar, request.caller, request.caller_agent
        )
        return runtime_pb2.ExecuteResponse(
            status=result.status,
            output=result.output,
            usage=common_pb2.Usage(
                input_tokens=result.input_tokens, output_tokens=result.output_tokens, cost_usd=result.cost_usd
            ),
            steps=[
                common_pb2.Step(
                    kind=s.kind,
                    name=s.name,
                    decision=s.decision,
                    rule=s.rule,
                    latency_ms=s.latency_ms,
                    summary=s.summary,
                )
                for s in result.steps
            ],
            rule=result.rule,
            reason=result.reason,
        )


async def serve(listen: str, sidecar_address: str) -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    server = grpc.aio.server()
    runtime_pb2_grpc.add_RuntimeServicer_to_server(RuntimeServicer(GrpcSidecar(sidecar_address)), server)
    server.add_insecure_port(listen)
    await server.start()
    log.info(
        "attache-runtime %s listening on %s, sidecar at %s, provider=%s",
        __version__,
        listen,
        sidecar_address,
        "anthropic" if anthropic_available() else "mock",
    )
    await server.wait_for_termination()
