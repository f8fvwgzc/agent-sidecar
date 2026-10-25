"""Entry point: `agentsc-runtime --listen unix:/run/agentsc/runtime.sock --sidecar unix:/run/agentsc/sidecar.sock`."""

from __future__ import annotations

import argparse
import asyncio
import os

from .models import GATEWAY_ENV, gateway_for_sidecar
from .server import serve


def main() -> None:
    p = argparse.ArgumentParser(prog="agentsc-runtime")
    p.add_argument("--listen", default="unix:/run/agentsc/runtime.sock", help="gRPC address to serve Runtime on")
    p.add_argument("--sidecar", default="unix:/run/agentsc/sidecar.sock", help="gRPC address of SidecarTools")
    p.add_argument(
        "--model-gateway",
        default=os.environ.get(GATEWAY_ENV),
        help="the sidecar's model gateway (default: env AGENTSC_MODEL_GATEWAY, else model.sock next to --sidecar)",
    )
    args = p.parse_args()
    asyncio.run(serve(args.listen, args.sidecar, args.model_gateway or gateway_for_sidecar(args.sidecar)))


if __name__ == "__main__":
    main()
