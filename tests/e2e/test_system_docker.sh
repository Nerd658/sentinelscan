#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

COMPOSE_FILE="$SCRIPT_DIR/docker-compose.lab.yml"
GO_BIN="/usr/local/go/bin/go"
DB_URL="postgresql://sentinel:sentinel_password@172.28.0.5:5432/sentinelscan?sslmode=disable"

echo "=================================================="
echo "    SENTINELSCAN PHASE 11 — DYNAMIC REALITY TEST   "
echo "=================================================="

cleanup() {
    echo ""
    echo "[NETTOYAGE] Arrêt du lab Docker..."
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Compilation préalable du binaire pour l'image runner
echo "[1/6] Compilation du binaire Linux SentinelScan..."
cd "$PROJECT_ROOT"
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $GO_BIN build -o "$PROJECT_ROOT/bin/sentinelscan" ./cmd/sentinelscan

# 2. Démarrage des conteneurs
echo "[2/6] Démarrage du cluster Docker Lab avec Healthchecks..."
docker compose -f "$COMPOSE_FILE" up -d --build

# 3. Polling strict des healthchecks (remplacement de sleep 5)
echo "[3/6] Vérification des Healthchecks des services..."
MAX_WAIT=30
WAIT_COUNT=0
UNHEALTHY=1

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    POSTGRES_HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' lab-postgres 2>/dev/null || echo "not_found")
    REDIS_HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' lab-redis 2>/dev/null || echo "not_found")
    NGINX_HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' lab-nginx 2>/dev/null || echo "not_found")

    if [ "$POSTGRES_HEALTH" = "healthy" ] && [ "$REDIS_HEALTH" = "healthy" ] && [ "$NGINX_HEALTH" = "healthy" ]; then
        UNHEALTHY=0
        echo "✓ Tous les conteneurs clés sont HEALTHY !"
        break
    fi

    echo "Attente des healthchecks... (Postgres: $POSTGRES_HEALTH, Redis: $REDIS_HEALTH, Nginx: $NGINX_HEALTH)"
    sleep 2
    WAIT_COUNT=$((WAIT_COUNT + 2))
done

if [ $UNHEALTHY -eq 1 ]; then
    echo "❌ ECHEC : Un ou plusieurs conteneurs n'ont pas validé leur Healthcheck !"
    docker compose -f "$COMPOSE_FILE" ps
    docker compose -f "$COMPOSE_FILE" logs postgres lab-nginx
    exit 1
fi

docker compose -f "$COMPOSE_FILE" ps

# 4. Scan initial #1 depuis le conteneur runner
echo ""
echo "[4/6] Scan Initial #1 — Exécution dans le conteneur sentinelscan-runner..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan scan jobsira.test

# 5. Test 1 — Disparition & réapparition d'un service (PORT_CLOSED & PORT_OPENED)
echo ""
echo "[5/6] Test de réalité dynamique 1 : Arrêt du service lab-api (PORT_CLOSED)..."
docker stop lab-api
sleep 2

echo "Exécution du Scan #2 (Vérification PORT_CLOSED)..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan scan jobsira.test

echo "Redémarrage du service lab-api (PORT_OPENED)..."
docker start lab-api
sleep 2

echo "Exécution du Scan #3 (Vérification PORT_OPENED)..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan scan jobsira.test

# 6. Lecture du rapport EASM final depuis la base PostgreSQL réelle
echo ""
echo "[6/6] Lecture du rapport EASM final depuis PostgreSQL via le CLI..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan report jobsira.test

echo ""
echo "=================================================="
echo "    PHASE 11 DYNAMIC REALITY TEST PASSED CLEANLY  "
echo "=================================================="
