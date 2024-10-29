#!/bin/sh

# Run the OpenSSL OCSP responder
openssl ocsp -index /etc/nginx/certs/index.txt \
              -CA /etc/nginx/certs/ca.crt \
              -rsigner /etc/nginx/certs/ocsp.crt \
              -rkey /etc/nginx/certs/ocsp.key \
              -port 8080 \
              -text