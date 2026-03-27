from __future__ import annotations

import json
from typing import Any

import psycopg
import redis
from psycopg.rows import dict_row

from services.shared.config import env


def pg_conn(service_name: str | None = None) -> psycopg.Connection:
    db_name = service_name or env("POSTGRES_DB", "app")
    return psycopg.connect(
        host=env("POSTGRES_HOST", "postgres"),
        port=env("POSTGRES_PORT", "5432"),
        user=env("POSTGRES_USER", "platform"),
        password=env("POSTGRES_PASSWORD", "platform"),
        dbname=db_name,
        row_factory=dict_row,
        autocommit=True,
    )


def redis_client() -> redis.Redis:
    return redis.Redis(
        host=env("REDIS_HOST", "redis"),
        port=int(env("REDIS_PORT", "6379")),
        decode_responses=True,
    )


def ensure_table(connection: psycopg.Connection, ddl: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute(ddl)


def redis_json_set(client: redis.Redis, key: str, value: Any) -> None:
    client.set(key, json.dumps(value))


def redis_json_get(client: redis.Redis, key: str, default: Any = None) -> Any:
    raw = client.get(key)
    if raw is None:
        return default
    return json.loads(raw)

