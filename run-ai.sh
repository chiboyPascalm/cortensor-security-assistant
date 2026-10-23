#!/bin/sh
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export OPENMINION_HOME="$PROJECT_DIR"
export OPENMINION_DATA_ROOT="$PROJECT_DIR/.openminion"
export OPENMINION_IDENTITY_ROOT="$PROJECT_DIR/.openminion/identity"
export OPENMINION_IDENTITY_DB="$PROJECT_DIR/.openminion/identity/identity.db"
exec "$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/app.py" --ai
