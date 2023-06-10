// createCerts.go
// program that generates certificates from Lets encrypt using the DNS Challenge
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
	"strings"

//    yaml "github.com/goccy/go-yaml"
	"golang.org/x/crypto/acme"
	"github.com/cloudflare/cloudflare-go"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "createCerts [domainfile]"
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
	if dbg {cfLib.PrintZoneList(zoneList)}

	numZones := len(zoneList.Zones)


	log.Printf("Acme Chal Domain Target: %d\n", numZones)
	if numZones == 0 {log.Fatalf("no domains in file: %s\n", zoneFilNam)}


	// read list of all domains for Acme Challenge
    csrList, err := certLib.ReadCsrFil(csrFilNam)
    if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	log.Printf("success reading CsrFile!\n")

	numAcmeDom := len(csrList.Domains)
    log.Printf("found %d acme Domains\n", numAcmeDom)

	if dbg {certLib.PrintCsr(csrList)}
	log.Printf("certDir: %s\n", csrList.CertDir)

	certDir := csrList.CertDir
	certdir := []byte(csrList.CertDir)
	if certdir[len(certdir) - 1] != '/' {certDir += "/"}
	log.Printf("certDir: %s\n", certDir)

	acmeDomList := make([]cfLib.ZoneAcme, numAcmeDom)
	// see whether acme domains are in zoneList

	count:=0
	for j:= 0; j< numAcmeDom; j++ {
		acmeDom := csrList.Domains[j].Domain
		for i:=0; i< numZones; i++ {
			if zoneList.Zones[i].Name == acmeDom {
				acmeDomList[j].Name = acmeDom
				acmeDomList[j].Id = zoneList.Zones[i].Id
				count++
				break
			}
		}
	}

	if count == 0 {log.Fatalf("no matching acme domains found in cf list")}

	numAcmeDom = count
    log.Printf("matched %d acme Domains\n", numAcmeDom)


	for j:= 0; j< numAcmeDom; j++ {
		log.Printf("acme domain [%d]: %20s id: %s\n", j+1, acmeDomList[j].Name, acmeDomList[j].Id)
	}


	// test acme domains for challenge records
	foundAcme := false
	for i:=0; i< numAcmeDom; i++ {
		acmeDomList[i].AcmeRec = false
		domain := acmeDomList[i].Name
		acmeDomain := "_acme-challenge." + domain

		log.Printf("performing ns.Lookup %s for DNS Challenge Record!\n", acmeDomain)

		txtrecs, err := net.LookupTXT(acmeDomain)
		if err == nil {
			log.Printf("received txtrec from Lookup\n")
			if dbg {fmt.Printf("txtrecs [%d]: %s\n", len(txtrecs), txtrecs[0])}
			acmeDomList[i].AcmeRec = true
			foundAcme = true
		} else {
			log.Printf("domain: %s -- no acme challenge record! %v", err)
		}
	}

	// get api for DNS use default yaml file
	cfapi, err := cfLib.InitCfApi("")
	if err != nil {log.Fatalf("cfLib.InitCfApi: %v\n", err)}
	log.Printf("success: init cfapi\n")

	// creating context
	ctx := context.Background()

	if foundAcme {
	// check acme target domains for left-over acme records
		log.Printf("checking for left-over acme records\n")
		var listDns cloudflare.ListDNSRecordsParams
		var rc cloudflare.ResourceContainer
		rc.Level = cloudflare.ZoneRouteLevel

		cf := cfapi.API

		for i:=0; i< numAcmeDom; i++ {
			if !acmeDomList[i].AcmeRec {continue}
			domain := acmeDomList[i].Name
			log.Printf("cleaning domain[%d]: %s\n", i+1, domain)
			rc.Identifier = acmeDomList[i].Id

    	    dnsRecs, _, err := cf.ListDNSRecords(ctx, &rc, listDns)
			if err != nil {log.Fatalf("domain[%d]: %s api.ListDNSRecords: %v\n", i+1, domain, err)}

			if dbg {cfLib.PrintDnsRecs(&dnsRecs)}
    	    dnsId := ""
        	for j:=0; j< len(dnsRecs); j++ {
            	idx := strings.Index(dnsRecs[j].Name, "_acme-challenge.")
            	if idx == 0 {
                	dnsId = dnsRecs[j].ID
					log.Printf("found acme challenge record[%d] in domain %s\n", j+1, domain)
					err = cf.DeleteDNSRecord(ctx, &rc, dnsId)
					if err != nil {log.Fatalf("api.DeleteDNSRecord: %v\n", err)}
					log.Println("deleted Acme Dns Record")
				}
			}
		}

		log.Printf("finished cleaning acme records\n")

		if dbg {
			for i:=0; i< numAcmeDom; i++ {
				domain := acmeDomList[i].Name
				log.Printf("testing domain[%d]: %s\n", i+1, domain)
        		rc.Identifier = acmeDomList[i].Id
	        	dnsRecs, _, err := cf.ListDNSRecords(ctx, &rc, listDns)
    	    	if err != nil {log.Fatalf("domain[%d]: %s api.ListDNSRecords: %v\n", i+1, domain, err)}
				cfLib.PrintDnsRecs(&dnsRecs)
			}
		}

		// need to test cleanup with lookup
		log.Printf("waiting 2 sec before performing ns.Lookup\n")
		time.Sleep(2 * time.Second)

		for i:=0; i< numAcmeDom; i++ {
			domain := acmeDomList[i].Name

			acmeDomain := "_acme-challenge." + domain
			log.Printf("performing ns.Lookup %s for DNS Challenge Record!\n", acmeDomain)

			txtrecs, err := net.LookupTXT(acmeDomain)
			if err != nil {
				log.Printf("domain: %s -- no acme challenge record! %v", err)
			} else {
				log.Printf("received txtrec from Lookup\n")
				if dbg {fmt.Printf("txtrecs [%d]: %s\n", len(txtrecs), txtrecs[0])}
			}
		}
		os.Exit(1)
	}

	log.Printf("Tested success: No old Acme Challenge Records found!")
	// create new acme client
	client, err := certLib.NewClient(ctx, dbg)
	if err != nil {log.Fatalf("newClient: %v\n", err)}

	log.Printf("success creating acme client!\n")
	if dbg {certLib.PrintClient(client)}

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

	if dbg {certLib.PrintAccount(acnt)}

	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(dir)}


//	numAcmeDom = 1
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

	log.Printf("received Authorization Order!\n")
	if dbg {certLib.PrintOrder(*order)}

	log.Printf("**** Begin Loop ****\n")
	// need to loop through domains

//	var ctx context.Context

	for i:=0; i< numAcmeDom; i++ {
		// acmeZone.Name and domain are the same..
		domain := authIdList[i].Value
		log.Printf("domain [%d]: %s\n", i+1, domain)

		url := order.AuthzURLs[i]
		acmeZone := acmeDomList[i]

		auth, err := client.GetAuthorization(ctx, url)
		if err != nil {log.Fatalf("client.GetAuthorisation: %v\n",err)}

		log.Printf("success getting authorization for domain: %s\n", domain)
		if dbg {certLib.PrintAuth(auth)}

		// Pick the DNS challenge, if any.
		var chal *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}

		if chal == nil {log.Fatalf("no dns-01 challenge avaliable for zone %s", domain)}

		log.Printf("success obtaining challenge\n")
		if dbg {certLib.PrintChallenge(chal, acmeZone.Name)}

		// Fulfill the challenge.
		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {log.Fatalf("dns-01 token for %s: %v", domain, err)}

		log.Printf("success obtaining Dns token: %s\n", val)

		recId, err := cfapi.AddDnsChalRecord(acmeZone, val)
		if err != nil {log.Fatalf("AddDnsChalRecord: %v", err)}
		acmeDomList[i].AcmeId = recId

		if dbg {
			rc.Identifier = acmeDomList[i].Id
	        dnsRecs, _, err := cf.ListDNSRecords(ctx, &rc, listDns)
    	    if err != nil {log.Fatalf("domain[%d]: %s api.ListDNSRecords: %v\n", i+1, domain, err)}
			cfLib.PrintDnsRecs(&dnsRecs)
		}

		log.Printf("success creating dns record!")

		// check DNS Record via LookUp
		acmeDomain := "_acme-challenge." + domain

		log.Printf("waiting 2 sec before performing ns.Lookup\n")
		time.Sleep(2 * time.Second)
		log.Printf("performing ns.Lookup %s for DNS Challenge Record!\n", acmeDomain)

		rdAttempt := -1
		for i:= 0; i< 5; i++ {
			txtrecs, err := net.LookupTXT(acmeDomain)
			if err == nil {
				log.Printf("received txtrec from Lookup\n")
				if dbg {fmt.Printf("txtrecs [%d]: %s\n", len(txtrecs), txtrecs[0])}
				rdAttempt = i;
				break
			} else {
				log.Printf("Lookup err: %v - sleeping %d\n", err, i+1)
				time.Sleep(10 * time.Second)
			}
		}

		if rdAttempt < 0 {log.Fatalf("could not find acme record: %v", err)}
		log.Printf("Lookup successful in %d attempts!\n", rdAttempt +1)

		// Let CA know we're ready. But are we? Is DNS propagated yet?
		log.Printf("sending Accept\n")
		chal2, err := client.Accept(ctx, chal) 
		if err != nil {
			log.Fatalf("dns-01 accept for %q: %v", domain, err)
		}
		if dbg {certLib.PrintChallenge(chal2, domain)}
    	log.Printf("Accept acknowledged\n")
		orderUrl := order.URI
		tmpord, err := client.GetOrder(ctx, orderUrl)
		if err !=nil {
			log.Fatalf("order error: %v\n", err)
		}
		if dbg {certLib.PrintOrder(*tmpord)}
	}

	os.Exit(1)

    log.Printf("waiting for order\n")
	certUrl := order.URI
	if dbg {log.Printf("order url: %s\n", certUrl)}

    	ord2, err := client.WaitOrder(ctx, certUrl)
    	if err != nil {
			if ord2 != nil {certLib.PrintOrder(*ord2)}
			log.Fatalf("client.WaitOrder: %v\n",err)
		}
		log.Printf("received order!\n")

//		if dbg {certLib.PrintOrder(*ord2)}

	for i:=0; i< numAcmeDom; i++ {

		csrData := csrList.Domains[i]
		//certLib.PrintCsr(csrData)
		domain := csrData.Domain
		log.Printf("generating certificate for domain: %s\n", domain)
		// get certificates
		certNam, err :=certLib.GenerateCertName(domain)
		if err != nil {log.Fatalf("GenerateCertName: %v", err)}

		keyFilNam := certDir + certNam + ".key"
		certFilNam := certDir + certNam + ".crt"
		log.Printf("key file: %s cert file: %s\n", keyFilNam, certFilNam)

		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("GenerateKey: %v\n",err)
		}
		log.Printf("Cert Request: key generated!\n")

		err = certLib.SaveKeyPem(certKey, keyFilNam)
		if err != nil {log.Fatalf("certLib.SaveKeypem: %v",err)}

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

		// write the pem encoded certificate chain to file
		log.Printf("Saving certificate to: %s", certFilNam)

		err = certLib.SaveCertsPem(derCerts, certFilNam)
        if err != nil {log.Fatalf("SaveCerts: %v\n",err)}

		// cleanup

		acmeZone := acmeDomList[i]

		err = cfapi.DelDnsChalRecord(acmeZone)
    	if err != nil {log.Fatalf("DelDnsChalRecord: %v\n",err)}
		log.Printf("deleted DNS Chal Record for zone: %s\n", acmeZone.Name)

	}

	log.Printf("success\n")
}

