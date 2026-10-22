#!/bin/sh
# Writes a 10-year self-signed certificate for localhost into /certs if missing.
set -eu
if [ -s /certs/cert.pem ] && [ -s /certs/key.pem ]; then
  echo "certgen: certificate already present, nothing to do"
  exit 0
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout /certs/key.pem -out /certs/cert.pem
# The API runs as distroless nonroot and reads the key from a shared volume.
chmod 0644 /certs/cert.pem /certs/key.pem
echo "certgen: wrote /certs/cert.pem and /certs/key.pem"
