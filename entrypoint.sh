#!/bin/bash
set -e

mkdir -p /data/db /data/log

INIT_FLAG="/data/db/.initialized"

echo "======================================"
echo "  VulnSamurai starting..."
echo "  MongoDB 4.4 (no AVX required)"
echo "======================================"

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

if [ ! -f "$INIT_FLAG" ]; then
    echo "[2/3] Initialising database..."

    APP_USER="${MONGO_APP_USER:-vsapp}"
    APP_PASS="${MONGO_APP_PASS:-vspassword123}"

    mongo --quiet vulnsamurai --eval "
        db.createUser({
            user: '${APP_USER}',
            pwd:  '${APP_PASS}',
            roles: [{ role: 'readWrite', db: 'vulnsamurai' }]
        });
        db.createCollection('users');
        db.createCollection('scans');
        db.createCollection('reports');
        db.createCollection('audit_logs');
        db.users.createIndex({ username: 1 }, { unique: true });
        db.users.createIndex({ email: 1 },    { unique: true });
        db.scans.createIndex({ user_id: 1 });
        db.reports.createIndex({ user_id: 1 });
        db.audit_logs.createIndex(
            { timestamp: 1 },
            { expireAfterSeconds: 7776000 }
        );
        print('done');
    "

    touch "$INIT_FLAG"
    echo "[2/3] Database ready."
else
    echo "[2/3] Database already set up."
fi

mongo --quiet admin --eval "db.adminCommand({ shutdown: 1 })" 2>/dev/null || true
sleep 2

echo "[3/3] Launching all services..."
echo "======================================"
echo "  http://localhost:3000"
echo "======================================"

exec /usr/bin/supervisord -n -c /etc/supervisor/conf.d/vulnsamurai.conf
