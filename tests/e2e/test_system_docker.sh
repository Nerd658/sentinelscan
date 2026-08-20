#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

COMPOSE_FILE="$SCRIPT_DIR/docker-compose.lab.yml"
GO_BIN="/usr/local/go/bin/go"
DB_URL="postgresql://sentinel:sentinel_password@172.28.0.5:5432/sentinelscan?sslmode=disable"

echo "=================================================="
echo " PHASE 12 — BLACK-BOX PRODUCTION PATH VALIDATION  "
echo "=================================================="

cleanup() {
    echo ""
    echo "[NETTOYAGE] Arrêt du cluster Docker Lab..."
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Compilation préalable du binaire de production Linux
echo "[1/7] Compilation du binaire de production SentinelScan CLI..."
cd "$PROJECT_ROOT"
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $GO_BIN build -o "$PROJECT_ROOT/bin/sentinelscan" ./cmd/sentinelscan

# 2. Démarrage des conteneurs du lab
echo "[2/7] Démarrage du cluster Docker Lab avec Healthchecks..."
docker compose -f "$COMPOSE_FILE" up -d --build

# 3. Polling strict des healthchecks
echo "[3/7] Polling strict des Healthchecks des services..."
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
    exit 1
fi

# 4. Scan Black-Box CLI #1 depuis le conteneur runner
echo ""
echo "[4/7] Exécution du Scan Black-Box CLI #1 (sentinelscan scan jobsira.test)..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan scan jobsira.test

# 5. Audit SQL Direct dans le conteneur PostgreSQL (Vérification de Persistance Réelle)
echo ""
echo "[5/7] Audit SQL direct dans la base PostgreSQL du conteneur lab-postgres..."
HOST_COUNT=$(docker exec lab-postgres psql -U sentinel -d sentinelscan -t -c "SELECT count(*) FROM hosts;" | tr -d '[:space:]')
PORT_COUNT=$(docker exec lab-postgres psql -U sentinel -d sentinelscan -t -c "SELECT count(*) FROM ports;" | tr -d '[:space:]')
CERT_COUNT=$(docker exec lab-postgres psql -U sentinel -d sentinelscan -t -c "SELECT count(*) FROM certificates;" | tr -d '[:space:]')
FINDING_COUNT=$(docker exec lab-postgres psql -U sentinel -d sentinelscan -t -c "SELECT count(*) FROM findings;" | tr -d '[:space:]')

echo "  -> Table 'hosts' rows : $HOST_COUNT"
echo "  -> Table 'ports' rows : $PORT_COUNT"
echo "  -> Table 'certificates' rows : $CERT_COUNT"
echo "  -> Table 'findings' rows : $FINDING_COUNT"

if [ "$HOST_COUNT" -eq 0 ] || [ "$PORT_COUNT" -eq 0 ]; then
    echo "❌ ECHEC AUDIT SQL : La base de données PostgreSQL contient 0 observation !"
    exit 1
fi

# 6. Test de transition dynamique (stop / start lab-api)
echo ""
echo "[6/7] Test de transition d'état à chaud (docker stop lab-api -> rescan)..."
docker stop lab-api
sleep 2

docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan scan jobsira.test

docker start lab-api
sleep 2

docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan scan jobsira.test

# 7. Lecture du rapport EASM final via le CLI Black-Box
echo ""
echo "[7/7] Lecture du rapport EASM final via sentinelscan report jobsira.test..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan report jobsira.test

echo ""
echo "=================================================="
echo " TRUE END-TO-END PRODUCTION PATH VALIDATED CLEAN  "
echo "=================================================="
