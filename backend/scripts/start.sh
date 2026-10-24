#!/bin/sh
set -eu

if [ "${TRUSTVAULT_MIGRATE_ON_START:-true}" = "true" ]; then
    echo "Applying database migrations before web startup"
    alembic -c /app/alembic.ini upgrade head
else
    echo "Skipping startup migrations because TRUSTVAULT_MIGRATE_ON_START=${TRUSTVAULT_MIGRATE_ON_START}"
fi

exec uvicorn backend.app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
