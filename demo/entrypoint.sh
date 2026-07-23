#!/bin/sh
cd /app && acf-sidecar &
echo "Waiting for sidecar..."
for i in $(seq 1 30); do
    [ -S /tmp/acf.sock ] && break
    sleep 1
done
python main.py