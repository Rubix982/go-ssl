# NGINX Server Conf

To simulate and test our changes, we will spin up an NGINX server with our cases.

## Step 1: Generate Self-Signed Certificates

For testing purposes, we can create self-signed certificates, including a certificate authority (CA) certificate, a server certificate, and an OCSP responder certificate.

### Create a Certificate Authority (CA)

```sh
# Create a private key for the CA
openssl genrsa -out ca.key 2048

# Create a self-signed CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/CN=Test CA"
```

### Generate a Server certificate

```sh
# Generate a private key for the server
openssl genrsa -out server.key 2048

# Create a certificate signing request (CSR) for the server
openssl req -new -key server.key -out server.csr -subj "/CN=ssl_diagnostics"

# Generate the server certificate signed by the CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 500 -sha256
```

### Generate an OCSP Responder Certificate

```sh
# Generate a private key for the OCSP responder
openssl genrsa -out ocsp.key 2048

# Create a CSR for the OCSP responder
openssl req -new -key ocsp.key -out ocsp.csr -subj "/CN=Test OCSP Responder"

# Generate the OCSP responder certificate signed by the CA
openssl x509 -req -in ocsp.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ocsp.crt -days 500 -sha256
```

## Addition to `/etc/host`

```text
127.0.0.1 saif.xyz
127.0.0.1 ssl_diagnostics.xyz
```

## Available URLs

Then you will have 4 URLs available to hit,

* https://ssl_diagnostics.xyz:443 <- SSL configuration
* https://ssl_diagnostics.xyz:80 <- HTTP
* https://saif.xyz:9443 <- SSL with Client auth
* https://saif.xyz:9444 <- SSL without Client auth
* http://saif.xyz:9445 <- HTTP (no-auth)
* https://saif.xyz:9446 <- HTTP (basic auth)
