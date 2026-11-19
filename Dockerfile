FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_TOOL_OPTIONS="-Xmx384m -XX:+UseSerialGC"
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    unzip \
    wget \
    ca-certificates \
    && wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -rf /tmp/jadx.zip /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

CMD ["python", "bot.py"]
