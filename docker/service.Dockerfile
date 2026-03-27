# syntax=docker/dockerfile:1.7
FROM python:3.13-slim

ARG SERVICE_DIR
ARG SERVICE_PORT=8000

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV SERVICE_DIR=${SERVICE_DIR}
ENV SERVICE_PORT=${SERVICE_PORT}

COPY requirements.txt /app/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r /app/requirements.txt

COPY . /app
RUN mkdir -p /app/generated
RUN python -m grpc_tools.protoc -I /app/proto --python_out=/app/generated --grpc_python_out=/app/generated /app/proto/inventory.proto

EXPOSE ${SERVICE_PORT}

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${SERVICE_PORT:-8000} --app-dir /app/${SERVICE_DIR}"]
