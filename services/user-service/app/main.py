from fastapi import FastAPI

from services.shared.observability import install_observability, observe_event
from services.shared.store import ensure_table, pg_conn

app = FastAPI(title="user-service")
logger = install_observability(app, "user-service")
db = pg_conn("users")

ensure_table(
    db,
    """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        tier TEXT NOT NULL DEFAULT 'standard',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
)


@app.get("/users/{user_id}")
async def get_user(user_id: str) -> dict:
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            cursor.execute(
                "INSERT INTO users(id, name, tier) VALUES (%s, %s, %s) RETURNING *",
                (user_id, f"user-{user_id}", "standard"),
            )
            row = cursor.fetchone()
            observe_event("user-service", "user_created")
    logger.info("Fetched user", extra={"user_id": user_id})
    return row

