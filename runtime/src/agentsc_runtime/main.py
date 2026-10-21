"""Entry point: `agentsc-runtime --listen unix:/run/agentsc/runtime.sock --sidecar unix:/run/agentsc/sidecar.sock`."""

from __future__ import annotations

import argparse
import asyncio

from .server import serve


def main() -> None:
    p = argparse.ArgumentParser(prog="agentsc-runtime")
    p.add_argument("--listen", default="unix:/run/agentsc/runtime.sock", help="gRPC address to serve Runtime on")
    p.add_argument("--sidecar", default="unix:/run/agentsc/sidecar.sock", help="gRPC address of SidecarTools")
    args = p.parse_args()
    asyncio.run(serve(args.listen, args.sidecar))


if __name__ == "__main__":
    main()
