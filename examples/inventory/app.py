"""inventory: a FastAPI service with zero agentsc SDK. Its stock-analyst agent lives in the sidecar."""

from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="inventory")

# The warehouse contact is PII on purpose: the sidecar's pii_redact guardrail must keep it inside the pod.
STOCK = {
    "WIDGET-1": {"sku": "WIDGET-1", "on_hand": 42, "reorder_point": 50, "warehouse": "north", "warehouse_contact": "ops-lead@example.com"},
    "GADGET-2": {"sku": "GADGET-2", "on_hand": 310, "reorder_point": 100, "warehouse": "south", "warehouse_contact": "south-ops@example.com"},
}
ADMIN = {"resets": 0}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/stock")
def list_stock():
    return {"items": list(STOCK.values())}


@app.get("/stock/{sku}")
def get_stock(sku: str):
    item = STOCK.get(sku.upper())
    if not item:
        raise HTTPException(404, f"unknown sku {sku}")
    return item


@app.post("/admin/reset")
def admin_reset(request: Request):
    # The app listens on 127.0.0.1 inside the pod, so this is reachable only through the sidecar,
    # and the inventory charter denies it to the orders ops-assistant.
    ADMIN["resets"] += 1
    return {"reset": True, "resets": ADMIN["resets"], "caller": request.headers.get("x-agentsc-caller", "direct")}
