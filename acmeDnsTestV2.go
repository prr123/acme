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
	"net"

    cfLib "acme/acmeDns/cfLib"
    yaml "github.com/goccy/go-yaml"
	"golang.org/x/crypto/acme"
//	"github.com/cloudflare/cloudflare-go"
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

	numarg := len(os.Args)

	useStr := "acmeDnsTest [domainfile]"
    zoneFilNam := "/home/peter/zones/cfDomainsShort.yaml"
	acmeDomainFilNam := "acmeDomains.yaml"

	if numarg > 2 {
		fmt.Println(useStr)
		fmt.Println("too many arguments in cl!")
		os.Exit(-1)
	}

	if numarg == 2 {
		if os.Args[1] == "help" {
			fmt.Println(useStr)
			os.Exit(1)
		}
		acmeDomainFilNam = os.Args[1]
	}

	log.Printf("Using zone file: %s\n", zoneFilNam)
	log.Printf("Using acme Domain file: %s\n", acmeDomainFilNam)

    zoneList, err := cfLib.ReadZoneShortFile(zoneFilNam)
    if err != nil {log.Fatalf("ReadZoneFileShort: %v\n", err)}

	log.Printf("success reading domains!\n")
	cfLib.PrintZoneList(zoneList)

	numZones := len(zoneList.Zones)

	log.Printf("Acme Chal Domain Target: %d\n", numZones)
	if numZones == 0 {log.Fatalf("no domains in file: %s\n", zoneFilNam)}

	// read list of Domains for Acme Challenge

	domains, err := rdDomain(acmeDomainFilNam)
    if err != nil {log.Fatalf("rdDomains: %v\n", err)}

	if len(domains) == 0 {log.Fatalf("no acme domains found in %s\n", acmeDomainFilNam)}
	PrintDomains(domains)

	acmeDomList := make([]cfLib.ZoneShort, len(domains))
	// see whether acme domains are in zoneList

	for j:= 0; j< len(domains); j++ {
		for i:=0; i< numZones; i++ {
			if zoneList.Zones[i].Name == domains[j] {
				acmeDomList[j].Name = domains[j]
				acmeDomList[j].Id = zoneList.Zones[i].Id
				break
			}
		}
	}

	for j:= 0; j< len(domains); j++ {
		fmt.Printf("acme domain: %20s id: %s\n", acmeDomList[j].Name, acmeDomList[j].Id)
	}

	// get api for DNS use default yaml file
	cfapi, err := cfLib.InitCfApi("")
	if err != nil {log.Fatalf("cfLib.InitCfApi: %v\n", err)}
	log.Printf("success: init cfapi\n")

	ctx := context.Background()

// mod 1: replace
//	client := acmeClient(ctx)

	dbg := true
	client, err := newClient(ctx, dbg)
	if err != nil {log.Fatalf("newClient: %v\n", err)}

	log.Printf("success creating acme client!\n")
	PrintClient(client)


	acnt, err := registerClient(ctx, client, dbg)
	if err != nil {log.Fatalf("registerClient: %v\n", err)}

	log.Printf("success registering client and creating account!")
	PrintAccount(acnt)

	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	PrintDir(dir)


	numAcmeDom := 1
//	numAcmeDom := len(domains)
	authIdList := make([]acme.AuthzID, numAcmeDom)

	// Authorize all domains provided in the cmd line args.
	for i:=0; i< numAcmeDom; i++ {
		authIdList[i].Type = "dns"
		authIdList[i].Value = acmeDomList[i].Name
	}

	// lets encrypt does not accept preauthorisation
	// var orderOpt acme.OrderOption
	// OrderOption is contains optional parameters regarding timing

	order, err := client.AuthorizeOrder(ctx, authIdList)
	if err != nil {log.Fatalf("client.AuthorizeOrder: %v\n",err)}

	log.Printf("success getting acme orders!\n")
	PrintOrder(*order)

	// need to loop through domains
	for i:=0; i< numAcmeDom; i++ {
		domain := authIdList[i].Value
		url := order.AuthzURLs[i]
		acmeZone := acmeDomList[i]

		auth, err := client.GetAuthorization(ctx, url)
		if err != nil {log.Fatalf("client.GetAuthorisation: %v\n",err)}

		log.Printf("success getting authorization for domain: %s\n", domain)
		PrintAuth(auth)

		// Pick the DNS challenge, if any.
		var chal *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}

		if chal == nil {log.Fatalf("no dns-01 challenge for %s", domain)}

		log.Printf("success obtaining challenge\n")
		PrintChallenge(chal, acmeZone.Name)

		// Fulfill the challenge.
		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {log.Fatalf("dns-01 token for %q: %v", acmeZone.Name, err)}

		log.Printf("success obtaining Dns Rec Value: %s\n", val)

		recId, err := cfapi.AddDnsChalRecord(acmeZone, val)
		if err != nil {log.Fatalf("CreateDnsRecord: %v", err)}

		log.Printf("success creating dns record!")

		// check DNS Record via LookUp
		acmeDomain := "_acme-challenge." + domain

		log.Printf("doing ns.Lookup %s for Challenge Record!\n", acmeDomain)
		log.Printf("wait 2 sec\n")
		time.Sleep(2 * time.Second)
		log.Printf("continue: LookUp acme Dns Rec\n")

		suc := false
		for i:= 0; i< 5; i++ {
			txtrecs, err := net.LookupTXT(acmeDomain)
			if err == nil {
				fmt.Printf("txtrecs [%d]: %s\n", len(txtrecs), txtrecs[0])
				suc = true;
				break
			} else {
				log.Printf("Lookup err: %v - sleeping %d\n", err, i+1)
				time.Sleep(10 * time.Second)
			}
		}

		if !suc {log.Fatalf("could not find acme record: %v", err)}
		log.Printf("Lookup successful!\n")

		// Let CA know we're ready. But are we? Is DNS propagated yet?
		log.Printf("sending Accept\n")
		if _, err := client.Accept(ctx, chal); err != nil {
			log.Fatalf("dns-01 accept for %q: %v", domain, err)
		}

		url = order.URI
    	log.Printf("**** waiting for order for domain: %s ****\n", url)
    	ord2, err := client.WaitOrder(ctx, url)
    	if err != nil {log.Fatalf("client.WaitOrder: %v\n",err)}

    	PrintOrder(*ord2)
		err = cfapi.DelDnsChalRecord(acmeZone, recId)
    	if err != nil {log.Fatalf("DelDnsChalRecord: %v\n",err)}
		log.Printf("deleted DNS Chal Record for zone: %s\n", acmeZone.Name)
	}

/*
	// All authorizations are granted. Request the certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
client.Authorize
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

// function that creates a new client
func newClient(ctx context.Context, dbg bool) (cl *acme.Client, err error) {

	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { return nil, fmt.Errorf("Generate Key: %v", err)}

	if dbg {log.Printf("newClient: key generated!\n")}

	client := &acme.Client{Key: akey}
	client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	if dbg {
		log.Printf("Directory Url: %s\n", client.DirectoryURL)
		log.Printf("success client created! printing client\n")
		PrintClient(client)
	}
	return client, nil
}

// registers client with the acme server
func registerClient(ctx context.Context, client *acme.Client, dbg bool)(ac *acme.Account, err error) {

	acnt, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	if err != nil { return nil, fmt.Errorf("client.Register: %v", err)}

	if dbg {
		log.Printf("success CA account generated\n")
		PrintAccount(acnt)
	}

	return acnt, nil
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



func PrintAccount (acnt *acme.Account) {

	fmt.Println("***************** Acme Account ******************")
	fmt.Printf("URI:    %s\n", acnt.URI)
	fmt.Printf("Status: %s\n", acnt.Status)
	fmt.Printf("Contacts [%d]:\n", len((*acnt).Contact))
	for i:=0; i< len((*acnt).Contact); i++ {
		fmt.Printf("Contact[%d]: %s\n", i, (*acnt).Contact[i])
	}
	fmt.Printf("OrdersURL:   %s\n", acnt.OrdersURL)
	fmt.Println (" *** non RFC 8588 terms:  ***")
	fmt.Printf("  AgreedTerms: %s\n", acnt.AgreedTerms)
	fmt.Printf("  Authz: %s\n", acnt.Authz)
	fmt.Println("***************** End Account ******************")
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

	fmt.Println("************** Acme Client ******************")
	fmt.Printf("Key: %v\n", client.Key)
	fmt.Printf("HTTPClient: %v\n",client.HTTPClient)
	fmt.Printf("Directory: %s\n", client.DirectoryURL)
	fmt.Printf("Retry: %v\n", client.RetryBackoff)
	fmt.Printf("UserAgent: %s\n",client.UserAgent)
	fmt.Printf("KID: %s\n", client.KID)
	fmt.Println("***************** End Client ******************")
}

func PrintAuth(auth *acme.Authorization) {
	fmt.Println("*********** authorization ***********")
	fmt.Printf("URI:    %s\n", auth.URI)
	fmt.Printf("Status: %s\n", auth.Status)
	fmt.Printf("Id typ: %s val: %s\n", auth.Identifier.Type, auth.Identifier.Value)
	ExpTimStr:= auth.Expires.Format(time.RFC1123)
	fmt.Printf("Expires %s\n", ExpTimStr)
	fmt.Printf("*** Challenges[%d] ***\n", len(auth.Challenges))
	for i, chal := range auth.Challenges {
		fmt.Printf("   [%d]: %s URI: %s Token: %s Status: %s err: %v\n", i+1, chal.Type, chal.URI, chal.Token, chal.Status, chal.Error)
	}
	fmt.Println("*********** end authorization ***********")
}

func PrintDomains(domains []string) {
	fmt.Printf("*****  domains: %d *******\n", len(domains))
    for i, domain := range domains {
        fmt.Printf("domain[%d]: %s\n", i+1, domain)
    }
	fmt.Printf("***** end domains *******\n")
}

func PrintDir(dir acme.Directory) {

	fmt.Println("********** Directory **********")
	fmt.Printf("AuthzUrl: %s\n", dir.AuthzURL)
	fmt.Printf("OrderUrl: %s\n", dir.OrderURL)
	fmt.Printf("RevokeUrl: %s\n", dir.RevokeURL)
	fmt.Printf("NonceUrl: %s\n", dir.NonceURL)
	fmt.Printf("KeyChangeUrl: %s\n", dir.KeyChangeURL)
	fmt.Printf("Meta Terms: %v\n",	dir.Terms)
	fmt.Printf("Meta Website: %s\n", dir.Website)
	fmt.Printf("Meta CAA: %s\n", dir.CAA)
	fmt.Printf("External Account Req: %v\n", dir.ExternalAccountRequired)
	fmt.Println("******* End Directory *********")
}

func PrintOrder(ord acme.Order) {
	fmt.Println("************ Order **************")
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
	fmt.Println("********* End Order **************")

}

func PrintChallenge(chal *acme.Challenge, domain string) {
	fmt.Printf("*************** %s Challenge ********\n", domain)
	fmt.Printf("Type: %s\n", chal.Type)
	fmt.Printf("URI:  %s\n", chal.URI)
	fmt.Printf("Token: %s\n", chal.Token)
	fmt.Printf("Status: %s\n", chal.Status)
	fmt.Printf("Validated: %s\n", chal.Validated.Format(time.RFC1123))
	fmt.Printf("Error: %v\n", chal.Error)
	fmt.Printf("*************** End Challenge ********\n")
}

