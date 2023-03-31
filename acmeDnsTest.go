// from: https://github.com/golang/go/issues/23198
// author: prr azul software
// date: 31 March 2023
//
// code copied to test
// may include some modifications made by the author to the original code
//

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/acme"
)

func main() {
	ctx := context.Background()
	client := acmeClient(ctx)

	// Authorize all domains provided in the cmd line args.
	for _, domain := range os.Args[1:] {
		authz, err := client.Authorize(ctx, domain)
		if err != nil {
			log.Fatal(err)
		}
		if authz.Status == acme.StatusValid {
			// Already authorized.
			continue
		}

		// Pick the DNS challenge, if any.
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			log.Fatalf("no dns-01 challenge for %q", domain)
		}

		// Fulfill the challenge.
		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			log.Fatalf("dns-01 token for %q: %v", domain, err)
		}
		// TODO: Implement. This depends on your DNS hosting.
		// The function must provision a TXT record containing
		// the val value under "_acme-challenge" name.
		if err := updateMyDNS(ctx, domain, val); err != nil {
			log.Fatalf("DNS update for %q: %v", domain, err)
		}
		// Let CA know we're ready. But are we? Is DNS propagated yet?
		if _, err := client.Accept(ctx, chal); err != nil {
			log.Fatalf("dns-01 accept for %q: %v", domain, err)
		}
		// Wait for the CA to validate.
		if _, err := client.WaitAuthorization(ctx, authz.URL); err != nil {
			log.Fatalf("authorization for %q failed: %v", domain, err)
		}
	}

	// All authorizations are granted. Request the certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	req := &x509.CertificateRequest{
		DNSNames: os.Args[1:],
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		log.Fatal(err)
	}
	crt, _, err := client.CreateCert(ctx, csr, 90*24*time.Hour, true /* inc. chain */)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Store cert key and crt ether as is, in DER format, or convert to PEM.
}

func newClient(ctx context.Context) *acme.Client {
	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	client := &acme.Client{Key: akey}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		log.Fatal(err)
	}
	return client
}
