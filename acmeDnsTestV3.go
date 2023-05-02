// progrom that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 31 March 2023
// copyright 2023 prr, azulsoftware
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
//    "crypto/x509/pkix"
//    "encoding/asn1"
//    "encoding/pem"

	"log"
	"fmt"
	"os"
	"time"
	"net"

//    yaml "github.com/goccy/go-yaml"
	"golang.org/x/crypto/acme"
//	"github.com/cloudflare/cloudflare-go"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)

	useStr := "acmeDnsTestV3 [domainfile]"
    zoneFilNam := "/home/peter/zones/cfDomainsShort.yaml"

	csrFilNam := "csrList.yaml"

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
		csrFilNam = os.Args[1]
	}

	log.Printf("Using zone file: %s\n", zoneFilNam)
	log.Printf("Using csr file: %s\n", csrFilNam)

	// reading all domain names served by cloudflare
    zoneList, err := cfLib.ReadZoneShortFile(zoneFilNam)
    if err != nil {log.Fatalf("ReadZoneFileShort: %v\n", err)}

	log.Printf("success reading all cf zones!\n")
	cfLib.PrintZoneList(zoneList)

	numZones := len(zoneList.Zones)


	log.Printf("Acme Chal Domain Target: %d\n", numZones)
	if numZones == 0 {log.Fatalf("no domains in file: %s\n", zoneFilNam)}

	// read list of all domains for Acme Challenge
    csrList, err := certLib.ReadCsrFil(csrFilNam)
    if err != nil {log.Fatalf("ReadCsrFil: %v", err)}

    certLib.PrintCsr(csrList)

	numAcmeDom := len(csrList.Domains)
    log.Printf("found %d acme Domains\n", numAcmeDom)

	acmeDomList := make([]cfLib.ZoneShort, numAcmeDom)
	// see whether acme domains are in zoneList

	for j:= 0; j< numAcmeDom; j++ {
		acmeDom := csrList.Domains[j].Domain
		for i:=0; i< numZones; i++ {
			if zoneList.Zones[i].Name == acmeDom {
				acmeDomList[j].Name = acmeDom
				acmeDomList[j].Id = zoneList.Zones[i].Id
				break
			}
		}
	}

	for j:= 0; j< numAcmeDom; j++ {
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
	client, err := certLib.NewClient(ctx, dbg)
	if err != nil {log.Fatalf("newClient: %v\n", err)}

	log.Printf("success creating acme client!\n")
	certLib.PrintClient(client)

//	acnt, err := certLib.ReadAcmeAcnt(savActFilNam)
//	if err != nil {
		log.Printf("Creating Account\n")
		acnt, err := certLib.RegisterClient(ctx, client, dbg)
		if err != nil {log.Fatalf("registerClient: %v\n", err)}
		log.Printf("success registering client and creating account!")
//		err = certLib.SaveAcmeAcnt(savAcntFilnam)
//		if err != nil {log.Fatalf("SaveAccount %v\n", err)}
//		log.Printf("success saving account!")
//	} else {
//		log.Printf("Found Account File!\n")
//	}

	certLib.PrintAccount(acnt)


	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	certLib.PrintDir(dir)


	numAcmeDom = 1
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
	certLib.PrintOrder(*order)

	// need to loop through domains
	for i:=0; i< numAcmeDom; i++ {
		domain := authIdList[i].Value
		url := order.AuthzURLs[i]
		acmeZone := acmeDomList[i]

		auth, err := client.GetAuthorization(ctx, url)
		if err != nil {log.Fatalf("client.GetAuthorisation: %v\n",err)}

		log.Printf("success getting authorization for domain: %s\n", domain)
		certLib.PrintAuth(auth)

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
		certLib.PrintChallenge(chal, acmeZone.Name)

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

    	certLib.PrintOrder(*ord2)
		err = cfapi.DelDnsChalRecord(acmeZone, recId)
    	if err != nil {log.Fatalf("DelDnsChalRecord: %v\n",err)}
		log.Printf("deleted DNS Chal Record for zone: %s\n", acmeZone.Name)

//	}


	// All authorizations are granted. Request the certificate.

//	for i:=0; i< numAcmeDom; i++ {
		csrData := csrList.Domains[i]
//    	certLib.PrintCsr(csrData)

		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("GenerateKey: %v\n",err)
		}
		log.Printf("Cert Request: key generated!\n")

		keyFilNam:= "cert.key"
		err = certLib.SaveKeyPem(certKey, keyFilNam)
		if err != nil {log.Fatalf("certLib.SaveKeypem: %v",err)}

//		var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

//		emailAddress := csrData.Email

/*
		nam := csrData.Name
		subj := pkix.Name{
			CommonName:         nam.CommonName,
			Country:            []string{nam.Country},
			Province:           []string{nam.Province},
			Locality:           []string{nam.Locality},
			Organization:       []string{nam.Organisation},
			OrganizationalUnit: []string{"Admin"},
		}

	    rawSubj := subj.ToRDNSequence()

//    	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
//        	{Type: oidEmailAddress, Value: emailAddress},
//		})

    	asn1Subj, _ := asn1.Marshal(rawSubj)
    	template := x509.CertificateRequest{
        	RawSubject:         asn1Subj,
//        	EmailAddresses:     []string{emailAddress},
        	SignatureAlgorithm: x509.ECDSAWithSHA256,
        	DNSNames: []string{csrData.Domain},
    	}
*/
		template := certLib.CreateCsrTpl(csrData)
		csr, err := x509.CreateCertificateRequest(rand.Reader, &template, certKey)
		if err != nil {	log.Fatalf("CreateCertReq: %v",err)}


		csrParse, err := x509.ParseCertificateRequest(csr)
		if err != nil {log.Fatalf("Error parsing certificate request: %v", err)}

		// need to compare csrParse and template
		fmt.Printf("csrParse: %v\n", csrParse)


		ordUrl := ord2.FinalizeURL

		derCerts, certUrl, err := client.CreateOrderCert(ctx, ordUrl, csr, true)
		if err != nil {log.Fatalf("CreateOrderCert: %v\n",err)}

		log.Printf("derCerts: %d certUrl: %s\n", len(derCerts), certUrl)

		certFilNam :="cert.crt"
		// write the pem encoded certificate chain to file
		log.Printf("Saving certificate to: %s", certFilNam)

		err = certLib.SaveCertsPem(derCerts, certFilNam)
        if err != nil {log.Fatalf("SaveCerts: %v\n",err)}
/*
		certs := make([]*x509.Certificate, len(derCerts))

		var pemData []string

		for i, asn1Data := range derCerts {
			if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
				return log.Fatalf("Cert [%d]: %v",i, err)
			}
            pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
                Type:  "CERTIFICATE",
                Bytes: certs[i].Raw,
            }))))

		}
		if err := os.WriteFile(certFilNam, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
			log.Fatalf("Error writing certificate file %q: %v", certFilNam, err)
		}
*/
	}

	log.Printf("success\n")
}

