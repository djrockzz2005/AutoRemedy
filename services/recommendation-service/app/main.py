from fastapi import FastAPI

from services.shared.observability import install_observability, observe_event
from services.shared.store import redis_client, redis_json_get, redis_json_set

app = FastAPI(title="recommendation-service")
logger = install_observability(app, "recommendation-service")
cache = redis_client()

DEFAULTS = {
    "starter": ["keyboard", "mouse", "usb-c-dock"],
    "gaming": ["gpu", "mechanical-keyboard", "monitor"],
    "mobile": ["charger", "stand", "earbuds"],
}


@app.get("/recommendations/{user_id}")
async def recommendations(user_id: str) -> dict:
    bucket = "starter"
    recs = redis_json_get(cache, f"recs:{bucket}")
    if recs is None:
        recs = DEFAULTS[bucket]
        redis_json_set(cache, f"recs:{bucket}", recs)
    observe_event("recommendation-service", "recommendation_served")
    logger.info("Generated recommendations", extra={"user_id": user_id})
    return {"user_id": user_id, "items": recs}

