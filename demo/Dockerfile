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
RUN pip install --no-cache-dir "/sdk/[scanners]" langgraph
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

COPY demo/agent/ ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]