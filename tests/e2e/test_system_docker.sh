#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

COMPOSE_FILE="$SCRIPT_DIR/docker-compose.lab.yml"
GO_BIN="/usr/local/go/bin/go"
DB_URL="postgresql://sentinel:sentinel_password@172.28.0.5:5432/sentinelscan?sslmode=disable"

echo "=================================================="
echo " PHASE 14 — CDN-AWARE ORIGIN DISCOVERY E2E LAB    "
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
    ORIGIN_HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' lab-origin 2>/dev/null || echo "not_found")

    if [ "$POSTGRES_HEALTH" = "healthy" ] && [ "$REDIS_HEALTH" = "healthy" ] && [ "$NGINX_HEALTH" = "healthy" ] && [ "$ORIGIN_HEALTH" = "healthy" ]; then
        UNHEALTHY=0
        echo "✓ Tous les conteneurs clés (Postgres, Redis, CDN Edge, Origin) sont HEALTHY !"
        break
    fi

    echo "Attente des healthchecks... (Postgres: $POSTGRES_HEALTH, Edge: $NGINX_HEALTH, Origin: $ORIGIN_HEALTH)"
    sleep 2
    WAIT_COUNT=$((WAIT_COUNT + 2))
done

if [ $UNHEALTHY -eq 1 ]; then
    echo "❌ ECHEC : Un ou plusieurs conteneurs n'ont pas validé leur Healthcheck !"
    docker compose -f "$COMPOSE_FILE" ps
    exit 1
fi

# 4. Enregistrement d'une observation historique (Corrélation Certificat -> IP) dans PostgreSQL
echo ""
echo "[4/7] Inscription d'une observation historique (Certificat -> IP 172.28.0.40) dans PostgreSQL..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan report jobsira.test >/dev/null 2>&1 || true

docker exec lab-postgres psql -U sentinel -d sentinelscan -c "
INSERT INTO certificates (id, fingerprint_sha256, subject_cn, issuer, san, first_seen, last_seen)
VALUES ('a1111111-1111-1111-1111-111111111111', 'sha256_mock_historical_jobsira', 'jobsira.test', 'jobsira.test', '[\"jobsira.test\", \"*.jobsira.test\"]'::jsonb, NOW() - INTERVAL '14 days', NOW() - INTERVAL '14 days')
ON CONFLICT (fingerprint_sha256) DO NOTHING;

INSERT INTO certificate_observations (id, certificate_id, ip, port, sni, first_seen, last_seen)
VALUES ('b1111111-1111-1111-1111-111111111111', 'a1111111-1111-1111-1111-111111111111', '172.28.0.40', 443, 'jobsira.test', NOW() - INTERVAL '14 days', NOW() - INTERVAL '14 days')
ON CONFLICT (certificate_id, ip, port, sni) DO NOTHING;
"

# 5. Scan Black-Box CLI #1 depuis le conteneur runner (Découverte CDN Edge vs Origin)
echo ""
echo "[5/7] Exécution du Scan Black-Box CLI (sentinelscan scan jobsira.test)..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan scan jobsira.test

# 6. Audit SQL direct dans la base PostgreSQL du conteneur lab-postgres
echo ""
echo "[6/7] Audit SQL direct dans la base PostgreSQL..."
FINDING_COUNT=$(docker exec lab-postgres psql -U sentinel -d sentinelscan -t -c "SELECT count(*) FROM findings WHERE candidate_ip = '172.28.0.40';" | tr -d '[:space:]')
EDGE_FINDINGS=$(docker exec lab-postgres psql -U sentinel -d sentinelscan -t -c "SELECT count(*) FROM findings WHERE candidate_ip = '172.28.0.20';" | tr -d '[:space:]')

echo "  -> Origin Finding (172.28.0.40) rows in DB : $FINDING_COUNT"
echo "  -> Edge Proxy (172.28.0.20) findings in DB  : $EDGE_FINDINGS (Should be 0, CDN is not an Origin)"

if [ "$FINDING_COUNT" -eq 0 ]; then
    echo "❌ ECHEC : L'Origin Server 172.28.0.40 n'a pas été confirmé dans les findings PostgreSQL !"
    exit 1
fi

if [ "$EDGE_FINDINGS" -gt 0 ]; then
    echo "❌ ECHEC : Le CDN Edge 172.28.0.20 a été faussement enregistré comme Origin Server !"
    exit 1
fi

# 7. Lecture du rapport EASM final via sentinelscan report
echo ""
echo "[7/7] Lecture du rapport EASM final via sentinelscan report jobsira.test..."
docker exec -e DATABASE_URL="$DB_URL" sentinelscan-runner /app/bin/sentinelscan report jobsira.test

echo ""
echo "=================================================="
echo " CDN-AWARE ORIGIN DISCOVERY PROVEN 100% IN LAB    "
echo "=================================================="
