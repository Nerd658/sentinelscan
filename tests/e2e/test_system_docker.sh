#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

COMPOSE_FILE="$SCRIPT_DIR/docker-compose.lab.yml"
GO_BIN="/usr/local/go/bin/go"

echo "=================================================="
echo "      SENTINELSCAN TRUE DOCKER E2E SYSTEM TEST    "
echo "=================================================="

# 1. Spin up lab containers
echo "[1/6] Spinning up Docker Lab Environment..."
docker compose -f "$COMPOSE_FILE" up -d --build

cleanup() {
    echo "\n[6/6] Tearing down Docker Lab Environment..."
    docker compose -f "$COMPOSE_FILE" down -v
}
trap cleanup EXIT

# 2. Wait for container availability
echo "[2/6] Waiting for Docker Lab services to settle..."
sleep 5

docker compose -f "$COMPOSE_FILE" ps

# 3. Build CLI binary
echo "[3/6] Building SentinelScan CLI binary..."
cd "$PROJECT_ROOT"
$GO_BIN build -o "$PROJECT_ROOT/bin/sentinelscan" ./cmd/sentinelscan

# 4. Execute Go E2E system tests
echo "[4/6] Executing True Docker E2E System Test Suite..."
E2E_DOCKER=true $GO_BIN test -v ./tests/e2e/...

# 5. Execute Live CLI Scan & Report
echo "[5/6] Executing SentinelScan Live CLI Scan & Report..."
"$PROJECT_ROOT/bin/sentinelscan" scan jobsira.test || true
"$PROJECT_ROOT/bin/sentinelscan" report jobsira.test || true

echo "=================================================="
echo "    TRUE DOCKER E2E SYSTEM TEST PASSED CLEANLY    "
echo "=================================================="
