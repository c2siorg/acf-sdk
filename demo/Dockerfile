FROM golang:1.25-alpine AS sidecar-builder

WORKDIR /build
COPY sidecar/ ./sidecar/
COPY policies/ ./policies/

WORKDIR /build/sidecar
RUN go build -o /acf-sidecar ./cmd/sidecar

FROM python:3.11-slim

COPY --from=sidecar-builder /acf-sidecar /usr/local/bin/acf-sidecar
COPY --from=sidecar-builder /build/policies /app/policies

WORKDIR /app
COPY sdk/python/ /sdk/
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir "/sdk/[scanners]"
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# The sidecar resolves config/sidecar.yaml relative to its working directory
# (/app), and policy_dir (../policies/v1) relative to that config file. Without
# this copy it silently falls back to built-in defaults, which carry an empty
# tool allowlist and a shorter signal_weights table than the shipped config.
COPY config/ /app/config/

COPY demo/agent/ ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
