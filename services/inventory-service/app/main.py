from __future__ import annotations

import asyncio
import os
import sys
from concurrent import futures

import grpc
from fastapi import FastAPI

sys.path.append("/app/generated")
import inventory_pb2  # type: ignore
import inventory_pb2_grpc  # type: ignore

from services.shared.observability import install_observability, observe_event
from services.shared.store import redis_client, redis_json_get, redis_json_set
from services.shared.tracing import extract_grpc_metadata

app = FastAPI(title="inventory-service")
logger = install_observability(app, "inventory-service")
cache = redis_client()

SEED_ITEMS = {
    "keyboard": {"available": 50, "price": 99.0},
    "mouse": {"available": 80, "price": 49.0},
    "gpu": {"available": 20, "price": 699.0},
    "monitor": {"available": 35, "price": 349.0},
    "charger": {"available": 120, "price": 29.0},
}


def get_item_state(item_id: str) -> dict:
    state = redis_json_get(cache, f"inventory:{item_id}")
    if state is None:
        state = SEED_ITEMS.get(item_id, {"available": 25, "price": 59.0})
        redis_json_set(cache, f"inventory:{item_id}", state)
    return state


class InventoryApi(inventory_pb2_grpc.InventoryServiceServicer):
    def GetItem(self, request, context):
        extract_grpc_metadata(context.invocation_metadata())
        state = get_item_state(request.item_id)
        return inventory_pb2.ItemReply(
            item_id=request.item_id,
            available=state["available"],
            price=state["price"],
        )

    def ReserveItem(self, request, context):
        extract_grpc_metadata(context.invocation_metadata())
        state = get_item_state(request.item_id)
        if state["available"] < request.quantity:
            logger.warning("Inventory reserve rejected", extra={"item_id": request.item_id})
            return inventory_pb2.ReserveReply(ok=False, message="insufficient_stock", remaining=state["available"])
        state["available"] -= request.quantity
        redis_json_set(cache, f"inventory:{request.item_id}", state)
        observe_event("inventory-service", "stock_reserved")
        logger.info("Reserved stock", extra={"item_id": request.item_id, "quantity": request.quantity})
        return inventory_pb2.ReserveReply(ok=True, message="reserved", remaining=state["available"])

    def RestoreStock(self, request, context):
        extract_grpc_metadata(context.invocation_metadata())
        state = get_item_state(request.item_id)
        state["available"] += request.quantity
        redis_json_set(cache, f"inventory:{request.item_id}", state)
        observe_event("inventory-service", "stock_restored")
        logger.info("Restored stock", extra={"item_id": request.item_id, "quantity": request.quantity})
        return inventory_pb2.ReserveReply(ok=True, message="restored", remaining=state["available"])


@app.get("/items/{item_id}")
async def item(item_id: str) -> dict:
    return get_item_state(item_id)


@app.post("/seed")
async def seed() -> dict:
    for item_id, state in SEED_ITEMS.items():
        redis_json_set(cache, f"inventory:{item_id}", state)
    observe_event("inventory-service", "inventory_seeded")
    return {"status": "seeded", "items": len(SEED_ITEMS)}


@app.on_event("startup")
async def start_grpc_server() -> None:
    async def run_server() -> None:
        server = grpc.aio.server()
        inventory_pb2_grpc.add_InventoryServiceServicer_to_server(InventoryApi(), server)
        listen_addr = f"[::]:{os.getenv('GRPC_PORT', '50051')}"
        server.add_insecure_port(listen_addr)
        await server.start()
        await server.wait_for_termination()

    asyncio.create_task(run_server())
