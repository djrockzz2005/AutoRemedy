#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}"
export PLATFORM_RETENTION_DAYS="${PLATFORM_RETENTION_DAYS:-14}"

python3 - <<'PY'
import os
from services.shared.maintenance import prune_tables

prune_tables(int(os.getenv("PLATFORM_RETENTION_DAYS", "14")))
PY
