#!/bin/bash
# Generate self-signed SSL certificates for PostgreSQL
# For production, use proper CA-signed certificates

set -e

CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

# Generate CA key and certificate
openssl genrsa -aes256 -out "$CERT_DIR/ca.key" -passout pass:capass 4096
openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -passin pass:capass \
    -subj "/C=US/ST=State/L=City/O=SafeNestT/CN=SafeNestT Root CA"

# Generate server key and certificate
openssl genrsa -aes256 -out "$CERT_DIR/server.key" -passout pass:serverpass 4096
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -passin pass:serverpass \
    -subj "/C=US/ST=State/L=City/O=SafeNestT/CN=postgres"

# Sign server cert with CA
openssl x509 -req -days 365 -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" \
    -passin pass:capass

# Set permissions
chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt" "$CERT_DIR/ca.crt"

# Remove passphrases for PostgreSQL (it can't use password-protected keys)
openssl rsa -in "$CERT_DIR/server.key" -out "$CERT_DIR/server.key.nopass" \
    -passin pass:serverpass
mv "$CERT_DIR/server.key.nopass" "$CERT_DIR/server.key"
chmod 600 "$CERT_DIR/server.key"

echo "Certificates generated in $CERT_DIR/"
echo "ca.crt: CA certificate (trust this)"
echo "server.crt: server certificate"
echo "server.key: server private key (no passphrase)"
