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

    # Create application user
    mongo vulnsamurai --eval "db.createUser({user: '$APP_USER', pwd: '$APP_PASS', roles: [{role: 'readWrite', db: 'vulnsamurai'}]})"

    # Create collections
    mongo vulnsamurai --eval 'db.createCollection("users")'
    mongo vulnsamurai --eval 'db.createCollection("scans")'
    mongo vulnsamurai --eval 'db.createCollection("vulns")'
    mongo vulnsamurai --eval 'db.createCollection("reports")'
    mongo vulnsamurai --eval 'db.createCollection("audit_logs")'

    # Create indexes
    mongo vulnsamurai --eval 'db.users.createIndex({email: 1}, {unique: true})'
    mongo vulnsamurai --eval 'db.users.createIndex({username: 1}, {unique: true})'
    mongo vulnsamurai --eval 'db.scans.createIndex({owner_id: 1})'
    mongo vulnsamurai --eval 'db.scans.createIndex({status: 1})'
    mongo vulnsamurai --eval 'db.scans.createIndex({created_at: -1})'
    mongo vulnsamurai --eval 'db.vulns.createIndex({owner_id: 1})'
    mongo vulnsamurai --eval 'db.vulns.createIndex({scan_id: 1})'
    mongo vulnsamurai --eval 'db.vulns.createIndex({severity: 1})'
    mongo vulnsamurai --eval 'db.vulns.createIndex({owner_id: 1, severity: 1, created_at: -1})'
    mongo vulnsamurai --eval 'db.audit_logs.createIndex({timestamp: 1}, {expireAfterSeconds: 7776000})'

    # Create default user: samurai/samurai
    # Using pre-computed bcrypt hash for password "samurai"
    DEFAULT_USER="samurai"
    DEFAULT_PASS_HASH="$2b$12$fflarM/06FPvN3e6.r1Kx.Ql0cCG3YPKXyGnBjWkVDlV.fZH9HmRm"
    mongo vulnsamurai --eval "
      db.users.updateOne(
        { username: '$DEFAULT_USER' },
        { 
          \$setOnInsert: {
            username: '$DEFAULT_USER',
            email: 'samurai@example.com',
            password_hash: '$DEFAULT_PASS_HASH',
            role: 'analyst',
            created_at: new Date(),
            last_login: null,
            is_active: true
          }
        },
        { upsert: true }
      )
    "

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
