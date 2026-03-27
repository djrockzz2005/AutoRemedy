# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder

ARG SERVICE_DIR
ARG SERVICE_PORT=8000
ARG SERVICE_NAME

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

COPY docker/requirements /app/docker/requirements
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r "/app/docker/requirements/${SERVICE_NAME}.txt"

COPY . /app
RUN mkdir -p /app/generated && \
    if python -c "import grpc_tools.protoc" >/dev/null 2>&1; then \
      python -m grpc_tools.protoc \
        -I /app/proto \
        --python_out=/app/generated \
        --grpc_python_out=/app/generated \
        /app/proto/inventory.proto; \
    fi

FROM python:3.12-slim AS runtime

ARG SERVICE_DIR
ARG SERVICE_PORT=8000
ARG SERVICE_NAME

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV SERVICE_DIR=${SERVICE_DIR}
ENV SERVICE_PORT=${SERVICE_PORT}
ENV SERVICE_NAME=${SERVICE_NAME}

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app

EXPOSE ${SERVICE_PORT}

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${SERVICE_PORT:-8000} --app-dir /app/${SERVICE_DIR}"]
