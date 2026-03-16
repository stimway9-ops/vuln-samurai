cat > Dockerfile << 'EOF'
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    nodejs npm \
    nikto whatweb gobuster sqlmap wapiti \
    supervisor curl unzip \
    && pip3 install fastapi uvicorn motor pydantic pydantic-settings \
       passlib bcrypt python-jose python-multipart httpx sse-starlette \
       --break-system-packages \
    && NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
       | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/') \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" \
       -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && apt-get clean

RUN mkdir -p /data/db /data/log /app/frontend/static

COPY backend/  /app/backend/
COPY frontend/ /app/frontend/

EOF
