cat > entrypoint.sh << 'EOF'
#!/bin/bash
mkdir -p /data/db /data/log
exec /usr/bin/supervisord -n -c /etc/supervisord.conf
EOF
