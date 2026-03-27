from __future__ import annotations

import os
import sys
import uuid

import grpc
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

sys.path.append("/app/generated")
import inventory_pb2  # type: ignore
import inventory_pb2_grpc  # type: ignore

from services.shared.observability import install_observability, observe_event
from services.shared.store import ensure_table, pg_conn, redis_client, redis_json_set

app = FastAPI(title="order-service")
logger = install_observability(app, "order-service")
db = pg_conn("orders")
cache = redis_client()

USER_SERVICE = os.getenv("USER_SERVICE_URL", "http://user-service:8000")
PAYMENT_SERVICE = os.getenv("PAYMENT_SERVICE_URL", "http://payment-service:8000")
INVENTORY_ADDR = os.getenv("INVENTORY_GRPC_ADDR", "inventory-service:50051")

ensure_table(
    db,
    """
    CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        quantity INT NOT NULL,
        amount DOUBLE PRECISION NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
)


class OrderRequest(BaseModel):
    user_id: str
    item_id: str
    quantity: int = 1


@app.post("/orders")
async def create_order(request: OrderRequest) -> dict:
    order_id = str(uuid.uuid4())
    async with httpx.AsyncClient(timeout=4.0) as client:
        user_response = await client.get(f"{USER_SERVICE}/users/{request.user_id}")
        user_response.raise_for_status()
    async with grpc.aio.insecure_channel(INVENTORY_ADDR) as channel:
        stub = inventory_pb2_grpc.InventoryServiceStub(channel)
        item_state = await stub.GetItem(inventory_pb2.ItemRequest(item_id=request.item_id))
        reserve = await stub.ReserveItem(
            inventory_pb2.ReserveRequest(item_id=request.item_id, quantity=request.quantity)
        )
    if not reserve.ok:
        raise HTTPException(status_code=409, detail=reserve.message)

    amount = item_state.price * request.quantity
    async with httpx.AsyncClient(timeout=4.0) as client:
        payment_response = await client.post(
            f"{PAYMENT_SERVICE}/charge",
            json={"user_id": request.user_id, "order_id": order_id, "amount": amount},
        )
        payment_response.raise_for_status()
    with db.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO orders(id, user_id, item_id, quantity, amount, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (order_id, request.user_id, request.item_id, request.quantity, amount, "confirmed"),
        )
    redis_json_set(
        cache,
        f"order:{order_id}",
        {
            "order_id": order_id,
            "item_id": request.item_id,
            "user_id": request.user_id,
            "status": "confirmed",
        },
    )
    observe_event("order-service", "order_confirmed")
    logger.info("Order confirmed", extra={"order_id": order_id, "item_id": request.item_id})
    return {
        "order_id": order_id,
        "amount": amount,
        "remaining_inventory": reserve.remaining,
        "status": "confirmed",
    }


@app.get("/orders/{order_id}")
async def get_order(order_id: str) -> dict:
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
        row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="order_not_found")
    return row

