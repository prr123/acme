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
//	"crypto/x509"
	"log"
	"fmt"
	"os"
//	"time"

	"golang.org/x/crypto/acme"
)

// yaml version of type acme.Account
type JsAcnt struct {
	// URI is the account unique ID, which is also a URL used to retrieve
	// account data from the CA.
	// When interfacing with RFC 8555-compliant CAs, URI is the "kid" field
	// value in JWS signed requests.
	URI string `yaml: "URI"`

	// Contact is a slice of contact info used during registration.
	// See https://tools.ietf.org/html/rfc8555#section-7.3 for supported
	// formats.
	Contact []string `yaml: "Contact"`

	// Status indicates current account status as returned by the CA.
	// Possible values are StatusValid, StatusDeactivated, and StatusRevoked.
	Status string `yaml: "Status"`

	// OrdersURL is a URL from which a list of orders submitted by this account
	// can be fetched.
	OrdersURL string `yaml: "OrdersURL"`

	// The terms user has agreed to.
	// A value not matching CurrentTerms indicates that the user hasn't agreed
	// to the actual Terms of Service of the CA.
	//
	// It is non-RFC 8555 compliant. Package users can store the ToS they agree to
	// during Client's Register call in the prompt callback function.
	AgreedTerms string `yaml: "Terms"`

	// Actual terms of a CA.
	//
	// It is non-RFC 8555 compliant. Use Directory's Terms field.
	// When a CA updates their terms and requires an account agreement,
	// a URL at which instructions to do so is available in Error's Instance field.
	CurrentTerms string `yaml: "CurTerms"`

	// Authz is the authorization URL used to initiate a new authz flow.
	//
	// It is non-RFC 8555 compliant. Use Directory's AuthzURL or OrderURL.
	Authz string `yaml: "Authz"`

	// Authorizations is a URI from which a list of authorizations
	// granted to this account can be fetched via a GET request.
	//
	// It is non-RFC 8555 compliant and is obsoleted by OrdersURL.
	Authorizations string `yaml: "Auth"`

	// Certificates is a URI from which a list of certificates
	// issued for this account can be fetched via a GET request.
	//
	// It is non-RFC 8555 compliant and is obsoleted by OrdersURL.
	Certificates string `yaml: "Certs"`

	// ExternalAccountBinding represents an arbitrary binding to an account of
	// the CA which the ACME server is tied to.
	// See https://tools.ietf.org/html/rfc8555#section-7.3.4 for more details.
	ExternalAccountBinding *acme.ExternalAccountBinding `yaml: "ExtAcct"`
}


func main() {
	ctx := context.Background()

// mod 1: replace
//	client := acmeClient(ctx)

	client := newClient(ctx)

//	fmt.Printf("client: %v\n", client)
	PrintClient(client)
	os.Exit(1)


}
// mod 2: get list of domains from cloudflare

/*
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

//		if err := updateMyDNS(ctx, domain, val); err != nil {
//			log.Fatalf("DNS update for %q: %v", domain, err)
//		}


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
	log.Printf("Cert Request: key generated!\n")

	// need to change domains
	req := &x509.CertificateRequest{
		DNSNames: os.Args[1:],
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		log.Fatal(err)
	}
	crt, _, err := client.CreateCert(ctx, csr, 90*24*time.Hour, true /* inc. chain )
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Store cert key and crt ether as is, in DER format, or convert to PEM.
}
*/

func newClient(ctx context.Context) *acme.Client {
	
	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("newClient: key generated!\n")
	client := &acme.Client{Key: akey}
	acnt, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS) 
	if err != nil {
		log.Fatal(err)
	}

	PrintAccount(acnt)

	jsAct := JsAcnt(*acnt)
	PrintJsAccount(&jsAct)

	log.Printf("newClient: registered successfully!\n")
	return client
}

func PrintAccount (acnt *acme.Account) {

	fmt.Println("***************** Acme Account ******************")
	fmt.Printf("URI:  %s\n", acnt.URI)
	fmt.Printf("Contacts [%d]:\n", len((*acnt).Contact))
	for i:=0; i< len((*acnt).Contact); i++ {
		fmt.Printf("Contact[%d]: %s\n", i, (*acnt).Contact[i])
	}
	fmt.Printf("OrdersURL:   %s\n", acnt.OrdersURL)
	fmt.Printf("AgreedTerms: %s\n", acnt.AgreedTerms)
}

func PrintJsAccount (acnt *JsAcnt) {

	fmt.Println("***************** Acme JsAccount ******************")
	fmt.Printf("URI:  %s\n", acnt.URI)
	fmt.Printf("Contacts [%d]:\n", len((*acnt).Contact))
	for i:=0; i< len((*acnt).Contact); i++ {
		fmt.Printf("Contact[%d]: %s\n", i, (*acnt).Contact[i])
	}
	fmt.Printf("OrdersURL:   %s\n", acnt.OrdersURL)
	fmt.Printf("AgreedTerms: %s\n", acnt.AgreedTerms)
}

func PrintClient (client *acme.Client) {

	fmt.Println("***************** Acme Client ******************")
	fmt.Printf("Key: %v\n", client.Key)
	fmt.Printf("HTTPClient: %v\n",client.HTTPClient)
	fmt.Printf("Directory: %s\n", client.DirectoryURL)
	fmt.Printf("Retry: %v\n", client.RetryBackoff)
	fmt.Printf("UserAgent: %s\n",client.UserAgent)
	fmt.Printf("KID: %s\n", client.KID)
}

