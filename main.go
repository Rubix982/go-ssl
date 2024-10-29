package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func main() {
	// Command-line flags for input
	host := flag.String("host", "localhost", "Host to check (e.g., example.com:443)")
	timeout := flag.Int("timeout", 5, "Connection timeout in seconds")
	flag.Parse()

	// Create a custom TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, // Change to true for testing purposes only
	}

	// Establish a connection
	conn, err := tls.Dial("tcp", *host, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect: %v\n", err)
	}
	defer conn.Close()

	// Get server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Fatal("No certificates found")
	}

	// Print certificate details and perform checks
	for _, cert := range certs {
		fmt.Printf("Certificate Subject: %s\n", cert.Subject)
		fmt.Printf("Certificate Issuer: %s\n", cert.Issuer)
		fmt.Printf("Certificate Validity: %s to %s\n", cert.NotBefore, cert.NotAfter)

		// Check if certificate is expired
		if time.Now().After(cert.NotAfter) {
			fmt.Println("Warning: Certificate is expired.")
		}

		// Check if the certificate is revoked using OCSP
		if err := checkRevocation(cert, conn.ConnectionState().PeerCertificates); err != nil {
			fmt.Printf("Warning: Certificate revocation check failed: %v\n", err)
		}

		// Verify hostname
		if err := cert.VerifyHostname(*host); err != nil {
			fmt.Printf("Warning: Hostname verification failed: %v\n", err)
		}

		// Check key usage
		if err := checkKeyUsage(cert); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	// Check the SSL/TLS version
	fmt.Printf("SSL/TLS version: %s\n", conn.ConnectionState().Version)

	// Optional: HTTP connection test for Basic Auth
	httpClient := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
	resp, err := httpClient.Get("https://" + *host)
	if err != nil {
		log.Fatalf("Failed to make HTTP request: %v\n", err)
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP Status Code: %d\n", resp.StatusCode)

	// Check for basic auth issues if applicable
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Warning: Authentication failed. Check your credentials.")
	}
}

// checkRevocation performs an OCSP check for certificate revocation
func checkRevocation(cert *x509.Certificate, certChain []*x509.Certificate) error {
	// Create an OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, certChain[0], nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %v", err)
	}

	// Assume the OCSP responder URL is available in the certificate's extensions
	ocspURL := cert.OCSPServer[0] // Simplification for demo; real code should handle multiple URLs

	// Send the OCSP request
	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspRequest))
	if err != nil {
		return fmt.Errorf("failed to send OCSP request: %v", err)
	}
	defer resp.Body.Close()

	// Parse the OCSP response
	ocspResponse, err := ocsp.ParseResponse(resp.Body, certChain[0])
	if err != nil {
		return fmt.Errorf("failed to parse OCSP response: %v", err)
	}

	// Check the response status
	switch ocspResponse.Status {
	case ocsp.Good:
		return nil // Certificate is good
	case ocsp.Revoked:
		return fmt.Errorf("certificate is revoked")
	case ocsp.Unknown:
		return fmt.Errorf("certificate status is unknown")
	default:
		return fmt.Errorf("unknown OCSP response status")
	}
}

// checkKeyUsage checks for supported key usage
func checkKeyUsage(cert *x509.Certificate) error {
	if !cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		return fmt.Errorf("Certificate does not support key encipherment")
	}
	if !cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		return fmt.Errorf("Certificate does not support digital signature")
	}
	return nil
}
