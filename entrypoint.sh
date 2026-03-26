#!/bin/bash
set -e

mkdir -p /data/db /data/log

# Load environment variables
if [ -f /app/.env ]; then
    export $(grep -v '^#' /app/.env | xargs)
fi

INIT_FLAG="/data/db/.initialized"

echo "======================================"
echo "  VulnSamurai starting..."
echo "  Python API + MongoDB 4.4"
echo "======================================"

# ── [1/3] Start MongoDB temporarily for init ──────────────────────────────────
echo "[1/3] Starting MongoDB..."
mongod --dbpath /data/db \
       --logpath /data/log/mongod_init.log \
       --bind_ip 127.0.0.1 \
       --port 27017 \
       --fork

echo "[1/3] Waiting for MongoDB..."
for i in $(seq 1 30); do
    mongo --quiet --eval "db.adminCommand('ping')" >/dev/null 2>&1 && break
    echo "  waiting... ($i/30)"
    sleep 1
done

# ── [2/3] Init DB (only on first boot) ───────────────────────────────────────
if [ ! -f "$INIT_FLAG" ]; then
    echo "[2/3] Initialising database..."

    APP_USER="${MONGO_APP_USER:-vsapp}"
    APP_PASS="${MONGO_APP_PASS:-vspassword123}"

    cat > /tmp/init.js << 'INITSCRIPT'
    db.createUser({
        user: '#{APP_USER}',
        pwd:  '#{APP_PASS}',
        roles: [{ role: 'readWrite', db: 'vulnsamurai' }]
    });
    db.createCollection('users');
    db.createCollection('scans');
    db.createCollection('vulns');
    db.createCollection('reports');
    db.createCollection('audit_logs');
    db.users.createIndex({ email: 1 }, { unique: true });
    db.users.createIndex({ username: 1 }, { unique: true });
    db.scans.createIndex({ owner_id: 1 });
    db.scans.createIndex({ status: 1 });
    db.scans.createIndex({ created_at: -1 });
    db.vulns.createIndex({ owner_id: 1 });
    db.vulns.createIndex({ scan_id: 1 });
    db.vulns.createIndex({ severity: 1 });
    db.vulns.createIndex({ owner_id: 1, severity: 1, created_at: -1 });
    db.audit_logs.createIndex({ timestamp: 1 }, { expireAfterSeconds: 7776000 });
    print('done');
    INITSCRIPT

    sed -i "s|#{APP_USER}|$APP_USER|g" /tmp/init.js
    sed -i "s|#{APP_PASS}|$APP_PASS|g" /tmp/init.js

    mongo vulnsamurai /tmp/init.js

    touch "$INIT_FLAG"
    echo "[2/3] Database ready."
else
    echo "[2/3] Database already set up, skipping init."
fi

# Shut down the temp mongod — supervisord will manage it from here
mongo --quiet admin --eval "db.adminCommand({ shutdown: 1 })" 2>/dev/null || true
sleep 2

# ── [3/3] Hand off to supervisord ────────────────────────────────────────────
echo "[3/3] Launching all services (mongodb + api + frontend)..."
echo "======================================"
echo "  http://localhost:3000"
echo "======================================"

exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/vulnsamurai.conf
