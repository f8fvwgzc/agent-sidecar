# attache-runtime

The Python half of the `attached` sidecar image. The sidecar spawns it with
`--listen unix:/run/attache/runtime.sock --sidecar unix:/run/attache/sidecar.sock`;
it serves `Runtime.Execute` and makes every tool call through `SidecarTools`.
See `../CONTRACT.md` §4.3 and §9.

```
uv sync
uv run pytest
uv run attache-runtime --listen unix:/tmp/rt.sock --sidecar unix:/tmp/sc.sock
```
