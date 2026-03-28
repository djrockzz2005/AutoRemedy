import os

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from services.shared.observability import install_observability, observe_event, traced_get, traced_post

app = FastAPI(title="api-gateway")
logger = install_observability(app, "api-gateway")

ORDER_SERVICE = os.getenv("ORDER_SERVICE_URL", "http://order-service:8000")
RECOMMENDATION_SERVICE = os.getenv("RECOMMENDATION_SERVICE_URL", "http://recommendation-service:8000")


class CheckoutRequest(BaseModel):
    user_id: str
    item_id: str
    quantity: int = 1


@app.post("/checkout")
async def checkout(request: CheckoutRequest) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        order_response = await traced_post(client, f"{ORDER_SERVICE}/orders", json=request.model_dump())
        order_response.raise_for_status()
        recs_response = await traced_get(client, f"{RECOMMENDATION_SERVICE}/recommendations/{request.user_id}")
        recs_response.raise_for_status()
    observe_event("api-gateway", "checkout_completed")
    logger.info("Checkout finished", extra={"user_id": request.user_id, "item_id": request.item_id})
    return {
        "order": order_response.json(),
        "recommendations": recs_response.json()["items"],
    }
