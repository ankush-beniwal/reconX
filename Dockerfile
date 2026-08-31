# =========================================================
# ReconX — single-command deployment image
# Bundles Go-based recon tools + Python orchestration layer.
# =========================================================
FROM golang:1.22-bookworm AS gobuilder

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery + community Go tools (pinned to @latest at build time;
# pin explicit versions for reproducible prod builds).
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/LukaSikic/subzy@latest && \
    go install -v github.com/Findomain/Findomain@latest 2>/dev/null || true

# ---------------------------------------------------------
FROM python:3.11-slim-bookworm

LABEL maintainer="reconx"
LABEL description="Modular async recon & asset discovery framework"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/go/bin:/opt/reconx/tools:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl wget unzip build-essential libpcap-dev massdns \
        ca-certificates dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy Go-built binaries from the builder stage.
COPY --from=gobuilder /go/bin/ /root/go/bin/

# Python deps
WORKDIR /opt/reconx
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Python tools available via pip (arjun, trufflehog installed separately if needed)
RUN pip install --no-cache-dir arjun

# Amass (official release binary — faster than `go install` for this tool)
RUN curl -sL https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -o /tmp/amass.zip \
    && unzip -q /tmp/amass.zip -d /tmp/amass \
    && mv /tmp/amass/*/amass /usr/local/bin/amass \
    && rm -rf /tmp/amass /tmp/amass.zip || echo "amass install skipped — install manually if needed"

# ffuf
RUN curl -sL $(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep browser_download_url | grep linux_amd64 | cut -d '"' -f4) -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
    && rm /tmp/ffuf.tar.gz || echo "ffuf install skipped — install manually if needed"

# App source
COPY . /opt/reconx

# Nuclei templates (fetched at build so first run isn't slow)
RUN nuclei -update-templates -silent || true

RUN mkdir -p /opt/reconx/data /opt/reconx/scope

VOLUME ["/opt/reconx/data", "/opt/reconx/scope", "/opt/reconx/config.yaml"]

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
