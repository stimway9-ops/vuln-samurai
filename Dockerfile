# ══════════════════════════════════════════════════════════════════════════════
#  VulnSamurai — single-container build
#  Services (managed by supervisord):
#    mongodb  → localhost:27017
#    api      → localhost:8000  (Python/FastAPI)
#    frontend → localhost:3000  (Node.js)
# ══════════════════════════════════════════════════════════════════════════════

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages + scan tools ──────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    curl wget gnupg unzip \
    supervisor \
    ca-certificates \
    libssl1.1 \
    nikto whatweb gobuster sqlmap wapiti \
    && mkdir -p /usr/share/wordlists \
    && wget -q -O /usr/share/wordlists/dirb/common.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt \
    && rm -rf /var/lib/apt/lists/*

# ── Python 3.9 ─────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 18 ────────────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# ── MongoDB 4.4 (no AVX required) ────────────────────────────────────────────
RUN wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | apt-key add - && \
    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" \
        > /etc/apt/sources.list.d/mongodb-org-4.4.list && \
    apt-get update && \
    apt-get install -y mongodb-org mongodb-org-shell && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Nuclei (latest) ──────────────────────────────────────────────────────────
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/') && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
        -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# ── Directories ───────────────────────────────────────────────────────────────
RUN mkdir -p /data/db /data/log /app/backend /app/frontend/static

# ── Backend (Python/FastAPI) ───────────────────────────────────────────────────
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip3 install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/ /app/backend/

# ── Frontend (Node.js) ────────────────────────────────────────────────────────
COPY frontend/ /app/frontend/
RUN cd /app/frontend && npm install --omit=dev

# ── Config files ───────────────────────────────────────────────────────────────
COPY supervisord.conf /etc/supervisor/conf.d/vulnsamurai.conf
COPY entrypoint.sh    /entrypoint.sh
COPY .env             /app/.env
RUN chmod +x /entrypoint.sh

EXPOSE 3000

ENTRYPOINT ["/entrypoint.sh"]
