#!/usr/bin/env bash
# seed the sample organisation once the database is reachable, then serve the dashboard and api.
set -e
echo "GraphOps: seeding the sample organisation..."
python -m app.seed || echo "GraphOps: seed failed (database may already hold data); continuing"
echo "GraphOps: starting the server on :8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
