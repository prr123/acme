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
	"time"

    yaml "github.com/goccy/go-yaml"
	"golang.org/x/crypto/acme"
)

type DomainObj struct {
    Domains []string `yaml:"domains"`
}

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
//	os.Exit(1)

// mod 2: read domains
    yamlFilNam := "domains.yaml"

    domains, err := rdDomain(yamlFilNam)
    if err != nil {log.Fatalf("rdDomain: %v\n", err)}

	PrintDomains(domains)

	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	PrintDir(dir)

	authIdList := make([]acme.AuthzID, len(domains))

	// Authorize all domains provided in the cmd line args.
	for i, domain := range domains {

		log.Printf("Domain[%d]: %s\n", i, domain)

		authIdList[i].Type = "dns"
		authIdList[i].Value = domain

	}
// lets encrypt does not accept preauthorisation
/*
		authz, err := client.Authorize(ctx, domain)
		if err != nil {log.Fatalf("client.Authorize: %v\n",err)}

		PrintAuth(authz)

		if authz.Status == acme.StatusValid {
			// Already authorized.
			continue
		}
*/

//	var orderOpt acme.OrderOption

	order, err := client.AuthorizeOrder(ctx, authIdList)
	if err != nil {log.Fatalf("client.AuthorizeOrder: %v\n",err)}

	PrintOrder(*order)




/*
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

		fmt.Printf("val: %s\n", val)

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
*/

/*
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
*/

	log.Printf("success\n")
}

func newClient(ctx context.Context) *acme.Client {

	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("newClient: key generated!\n")

	client := &acme.Client{Key: akey}
	client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	PrintClient(client)

	acnt, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		log.Fatal(err)
	}

	PrintAccount(acnt)


//	jsAct := JsAcnt(*acnt)

//	PrintJsAccount(&jsAct)

	log.Printf("newClient: registered successfully!\n")
	return client
}

func PrintAccount (acnt *acme.Account) {

	fmt.Println("***************** Acme Account ******************")
	fmt.Printf("URI:    %s\n", acnt.URI)
	fmt.Printf("Status: %s\n", acnt.Status)
	fmt.Printf("Contacts [%d]:\n", len((*acnt).Contact))
	for i:=0; i< len((*acnt).Contact); i++ {
		fmt.Printf("Contact[%d]: %s\n", i, (*acnt).Contact[i])
	}
	fmt.Printf("OrdersURL:   %s\n", acnt.OrdersURL)
	fmt.Println (" *** non RFC 8588 compliant terms  ***")
	fmt.Printf("AgreedTerms: %s\n", acnt.AgreedTerms)
	fmt.Printf("Authz: %s\n", acnt.Authz)
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

func PrintAuth(auth *acme.Authorization) {
	fmt.Println("*********** authorization ***********")
	fmt.Printf("URI:    %s\n", auth.URI)
	fmt.Printf("Status: %s\n", auth.Status)
	fmt.Printf("Id:     %s\n", auth.Identifier)
	ExpTimStr:= auth.Expires.Format(time.RFC1123)
	fmt.Printf("Expires %s\n", ExpTimStr)
	for i, chal := range auth.Challenges {
		fmt.Printf("chal[%d]: %s URI: %s Token: %s Status: %s err: %v\n", i+1, chal.Type, chal.URI, chal.Token, chal.Status, chal.Error)
	}
}

func PrintDomains(domains []string) {
	fmt.Printf("*****  domains: %d *******\n", len(domains))
    for i, domain := range domains {
        fmt.Printf("domain[%d]: %s\n", i+1, domain)
    }
}

func PrintDir(dir acme.Directory) {

	fmt.Println("**** Directory *****")
	fmt.Printf("AuthzUrl: %s\n", dir.AuthzURL)
	fmt.Printf("OrderUrl: %s\n", dir.OrderURL)
	fmt.Printf("RevokeUrl: %s\n", dir.RevokeURL)
	fmt.Printf("NonceUrl: %s\n", dir.NonceURL)
	fmt.Printf("KeyChangeUrl: %s\n", dir.KeyChangeURL)
	fmt.Printf("Meta Terms: %v\n",	dir.Terms)
	fmt.Printf("Meta Website: %s\n", dir.Website)
	fmt.Printf("Meta CAA: %s\n", dir.CAA)
	fmt.Printf("External Account Req: %v\n", dir.ExternalAccountRequired)

}

func PrintOrder(ord acme.Order) {
	fmt.Println("******* Order ***********")
	fmt.Printf("URI: %s\n", ord.URI)
	fmt.Printf("Status: %s\n", ord.Status)
	fmt.Printf("Expires: %s\n", ord.Expires.Format(time.RFC1123))
	fmt.Printf("Identifiers: %d\n", len(ord.Identifiers))
	for i:= 0; i< len(ord.Identifiers); i++ {
		id := ord.Identifiers[i]
		fmt.Printf("  id[%d]: typ: %s val %s\n", i+1, id.Type, id.Value)
	}
	fmt.Printf("Authorisation URLs: %d\n", len(ord.AuthzURLs))
	for i:= 0; i< len(ord.AuthzURLs); i++ {
		id := ord.AuthzURLs[i]
		fmt.Printf("  auth for id[%d]: %s\n", i+1, id)
	}
	fmt.Printf("FinalizeURL: %s\n", ord.FinalizeURL)
	fmt.Printf("CertURL: %s\n", ord.CertURL)
	fmt.Printf("error: %v\n", ord.Error)

}

// function that reads the file with name filNam and returns an array of domain names
func rdDomain(filNam string) (doms []string, err error) {

    var dom DomainObj

    data, err := os.ReadFile(filNam)
    if err != nil {return nil, fmt.Errorf("os.ReadFile: %v", err)}

    err = yaml.Unmarshal(data, &dom)
    if err != nil { return nil, fmt.Errorf("yaml.Unmarshal: %v", err)}

    return dom.Domains, nil
}
