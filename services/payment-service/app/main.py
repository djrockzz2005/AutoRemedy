from fastapi import FastAPI
from pydantic import BaseModel

from services.shared.observability import install_observability, observe_event
from services.shared.store import ensure_table, pg_conn

app = FastAPI(title="payment-service")
logger = install_observability(app, "payment-service")
db = pg_conn("payments")

ensure_table(
    db,
    """
    CREATE TABLE IF NOT EXISTS charges (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        amount DOUBLE PRECISION NOT NULL,
        order_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
)


class ChargeRequest(BaseModel):
    user_id: str
    order_id: str
    amount: float


@app.post("/charge")
async def charge(request: ChargeRequest) -> dict:
    status = "approved"
    with db.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO charges(user_id, amount, order_id, status)
            VALUES (%s, %s, %s, %s)
            RETURNING id, status
            """,
            (request.user_id, request.amount, request.order_id, status),
        )
        row = cursor.fetchone()
    observe_event("payment-service", "charge_processed")
    logger.info("Processed payment", extra={"order_id": request.order_id, "status": status})
    return {"charge_id": row["id"], "status": row["status"]}

