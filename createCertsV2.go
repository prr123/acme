// createCertsV2.go
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

	"log"
	"fmt"
	"os"
	"time"
	"net"
	"strings"

//    yaml "github.com/goccy/go-yaml"
	"golang.org/x/crypto/acme"
//	"github.com/cloudflare/cloudflare-go"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	var order *acme.Order
//	var clientDir acme.Directory
//	var acnt *acme.Account

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "./createCerts"
	helpStr := "program that creates certs for all domains listed in the file csrList.yaml\n"
	helpStr += "requirements: - a file listing all cloudflare domains/zones controlled by this account\n"
	helpStr += "              - a cloudflare authorisation file with a token that permits DNS record changes in the direcory cloudflare/token\n"

	zoneDir := os.Getenv("zoneDir")
	if len(zoneDir) == 0 {log.Fatalf("could not resolve env var zoneDir!")}

	certDir := os.Getenv("certDir")
	if len(certDir) == 0 {log.Fatalf("could not resolve env var certDir!")}

    zoneFilnam := zoneDir + "/cfDomainsShort.yaml"

	csrFilnam := "csrList.yaml"

    cfDir := os.Getenv("Cloudflare")
	if len(cfDir) == 0 {log.Fatalf("could not resolve env var cfDir!")}

    cfApiFilnam := cfDir + "/token/cfDns.yaml"

	if numarg > 2 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg < 1 {
		fmt.Println("insufficient arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg == 2 {
		if os.Args[1] == "help" {
			fmt.Printf("help: ")
			fmt.Printf("usage is: %s\n", useStr)
			fmt.Printf("\n%s\n", helpStr)
			os.Exit(1)
		}
		csrFilnam = os.Args[1]
	}

	log.Printf("Using zone file: %s\n", zoneFilnam)
	log.Printf("Using csr file: %s\n", csrFilnam)

	cfApiObj, err := cfLib.InitCfApi(cfApiFilnam)
	if err != nil {log.Fatalf("cfLib.InitCfApi: %v\n", err)}
	log.Printf("success: init cf api\n")

    // creating context
    ctx := context.Background()

	// reading all domain names served by cloudflare
    zoneList, err := cfLib.ReadZoneShortFile(zoneFilnam)
    if err != nil {log.Fatalf("ReadZoneFileShort: %v\n", err)}

	log.Printf("success reading all cf zones!\n")
	if dbg {cfLib.PrintZoneList(zoneList)}

	numZones := len(zoneList.Zones)

	log.Printf("Acme Chal Domain Target: %d\n", numZones)
	if numZones == 0 {log.Fatalf("no domains in file: %s\n", zoneFilnam)}


	// read list of all domains for Acme Challenge
    csrList, err := certLib.ReadCsrFil(csrFilnam)
    if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	log.Printf("success reading CsrFile!\n")

	numAcmeDom := len(csrList.Domains)
    log.Printf("found %d acme Domains\n", numAcmeDom)

	authIdList := make([]acme.AuthzID, numAcmeDom)

	if dbg {certLib.PrintCsr(csrList)}

	acmeDomList := make([]cfLib.ZoneAcme, numAcmeDom)
	// see whether acme domains are in zoneList

	chalList := make([]acme.Challenge, numAcmeDom)

	// get api for DNS use default yaml file

	foundAllDom := true
	for i:= 0; i< numAcmeDom; i++ {
		acmeDomNam := csrList.Domains[i].Domain
		foundDom := false
		for j:=0; j< numZones; j++ {
			if zoneList.Zones[j].Name == acmeDomNam {
				acmeDomList[i].Name = acmeDomNam
				acmeDomList[i].Id = zoneList.Zones[j].Id
				foundDom = true
				break
			}
		}
		if !foundDom {
			log.Printf("domain %s is not contained in the cf Zone List\n", acmeDomNam)
			foundAllDom = false
		}
	}

	if !foundAllDom {log.Fatalf("csr list file contains domains that are not in the cf account domain list!")}

	// check whether acme domains have challenge records
	// outcome is:
	// - all
	// - partial
	// - none

	allChalRec := true
	noChalRec := true
	for i:=0; i< numAcmeDom; i++ {
		recId := csrList.Domains[i].ChalRecId
		if len(recId) >0 {
			noChalRec = false
		} else {
			allChalRec = false
		}
	}

	log.Printf("allChalRec %t noChalRec %t\n", allChalRec, noChalRec)

	if !allChalRec && !noChalRec {log.Fatalf("error mixed: neither allChal nor noChal are true")}
	if allChalRec && noChalRec {log.Fatalf("error mixed: allChal and noChal cannot both be true")}

	// test acme domains for challenge records
	log.Printf("searching for left-over acme records!")
	oldAcmeRec := false
	noAcmeRec := true
	for i:=0; i< numAcmeDom; i++ {
		acmeDomList[i].AcmeRec = false
		domain := acmeDomList[i].Name
		acmeDomain := "_acme-challenge." + domain

		log.Printf("performing ns.Lookup %s for DNS Challenge Record!\n", acmeDomain)

		txtrecs, err := net.LookupTXT(acmeDomain)
		if err == nil {
			log.Printf("received txtrec from Lookup\n")
			if dbg {
				fmt.Printf("txtrecs[%d]: %s\n", len(txtrecs), txtrecs[0])
				fmt.Printf("token:       %s\n", csrList.Domains[i].TokVal)
			}
			if len(txtrecs[0]) > 0 {noAcmeRec = false}
			if txtrecs[0] != csrList.Domains[i].TokVal {
				acmeDomList[i].AcmeRec = true
				oldAcmeRec = true
			}
		} else {
			errStr := err.Error()
			log.Printf("*** errStr: %s\n", errStr)
			idx := strings.Index(errStr, "127.0.0.53:53")
			if idx>-1 {
				log.Printf("domain: %s -- no acme challenge record!", acmeDomain)
			} else {
				log.Fatalf("domain: %s -- lookup: %v", acmeDomain, err)
			}
		}
	}

	if oldAcmeRec {log.Fatalf("lookup found acme Dns chal records!")}

	if noAcmeRec {
		log.Printf("lookup no OldAcme Recs or new Acme Recs found\n")
	} else {
		log.Printf("lookup no OldAcme Recs but new Acme Recs found\n")
	}

    client, err := certLib.GetAcmeClient()
    if err != nil {log.Fatalf("could not get Acme Client: certLib.GetLEAcnt: %v\n", err)}
	log.Printf("success obtaining Acme Client\n")

    acnt, err := client.GetReg(ctx, "")
    if err != nil {log.Fatalf("could not find LE Client Account: getReg: %v\n", err)}
	if dbg {certLib.PrintAccount(acnt)}
	log.Printf("success retrieving LE Account\n")

	clientDir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("could not retrieve LE Directory: Discover: %v\n", err)}
	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(clientDir)}

	lookup:= true

	if allChalRec {
		log.Printf("found all domains contain acme chal recs; going to lookup!")
		goto ProcOrder
	}

	// Authorize all domains provided in the cmd line args.
	for i:=0; i< numAcmeDom; i++ {
		authIdList[i].Type = "dns"
		authIdList[i].Value = acmeDomList[i].Name
	}

	// lets encrypt does not accept preauthorisation
	// var orderOpt acme.OrderOption
	// OrderOption is contains optional parameters regarding timing

	order, err = client.AuthorizeOrder(ctx, authIdList)
	if err != nil {log.Fatalf("client.AuthorizeOrder: %v\n",err)}
	log.Printf("received Authorization Order!\n")
	if dbg {certLib.PrintOrder(*order)}

	log.Printf("**** Begin Loop ****\n")
	// need to loop through domains

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

		if chal == nil {log.Fatalf("dns-01 challenge is not available for zone %s", domain)}

		chalList[i] = *chal

		log.Printf("success obtaining challenge\n")
		if dbg {certLib.PrintChallenge(chal, acmeZone.Name)}

		// Fulfill the challenge.
		tokVal, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {log.Fatalf("dns-01 token for %s: %v", domain, err)}
		log.Printf("success obtaining Dns token: %s\n", tokVal)

		recId, err := cfApiObj.AddDnsChalRecord(acmeZone.Id, tokVal)
		if err != nil {log.Fatalf("AddDnsChalRecord: %v", err)}
		acmeDomList[i].AcmeId = recId

		csrList.Domains[i].TokVal = tokVal
		csrList.Domains[i].Token = chal.Token
		csrList.Domains[i].TokUrl = chal.URI
		csrList.Domains[i].ChalRecId = recId
		csrList.Domains[i].TokIssue = time.Now()
		csrList.Domains[i].TokExp = auth.Expires

		if dbg {
			zoneId := acmeDomList[i].Id
	        dnsRecs, err := cfApiObj.ListDnsRecords(zoneId)
    	    if err != nil {log.Fatalf("domain[%d]: %s apiObj.ListDnsRecords: %v\n", i+1, acmeDomList[i].Name, err)}
			cfLib.PrintDnsRecs(dnsRecs)
		}

		log.Printf("%s: success creating dns record!\n", acmeDomList[i].Name)

	}
	log.Printf("success creating all dns challenge records!")

	csrList.LastLU = time.Now()
	csrList.OrderUrl = order.URI
	err = certLib.WriteCsrFil(csrFilnam, csrList)
	if err != nil {log.Fatal("certLib.WriteCsrFil: %v\n", err)}

//	os.Exit(1)

	// we need to check whether newly add Dns Records have propagated
	log.Printf("performing lookup for all challenge records")

	for i:=0; i< numAcmeDom; i++ {
		domain := authIdList[i].Value

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
				// need to parse err for 127.0.0.53:53
				errStr := err.Error()
				log.Printf("*** errStr: %s\n", errStr)
				idx := strings.Index(errStr, "127.0.0.53:53")
				if idx>-1 {
					log.Printf("domain: %s -- no acme challenge record!", acmeDomain)
				} else {
					log.Fatalf("domain: %s -- lookup: %v", acmeDomain, err)
				}
//				log.Printf("Lookup no acme chal rec found! -- sleeping %d\n", i+1)
				time.Sleep(10 * time.Second)
			}
		}

		if rdAttempt < 0 {
			log.Printf("domain: %s: could not look-up acme record!", domain)
			lookup = false
		} else {
			log.Printf("domain: %s: Lookup successful in %d attempts!\n", domain, rdAttempt +1)
		}
	}

	if !lookup {
		log.Printf("Could not lookup Acme Chal records for all domains!\n")
		os.Exit(1)
	}

	//  at this point the dns chal records are all propaged. So we can process the challenge
ProcOrder:
	log.Printf("arrived at ProcOrd\n")

//	orderUrl := order.URI
	orderUrl := csrList.OrderUrl
	if len(orderUrl) == 0 {log.Fatalf("no order Url in CsrListFile!\n")}

	// ready for sending an accept; checked dns propogation with lookup
	for i:=0; i< numAcmeDom; i++ {
		dom := csrList.Domains[i]
		chalVal := acme.Challenge{
			Type: "dns-01",
			URI: dom.TokUrl,
			Token: dom.Token,
			Status: "pending",
		}
		if dbg {certLib.PrintChallenge(&chalVal, dom.Domain)}

		domain := dom.Domain
		log.Printf("sending Accept for domain %s\n", domain)

//		chalVal := chalList[i]

		chal2, err := client.Accept(ctx, &chalVal)
		if err != nil {log.Fatalf("dns-01 chal not accepted for %s: %v", domain, err)}
		if dbg {certLib.PrintChallenge(chal2, domain)}
 		log.Printf("chal accepted for domain %s\n", domain)

	}

	tmpord, err := client.GetOrder(ctx, orderUrl)
	if err !=nil {log.Fatalf("order error: %v\n", err)}
	if dbg {certLib.PrintOrder(*tmpord)}

    log.Printf("waiting for order\n")
	certUrl := order.URI
	if dbg {log.Printf("order url: %s\n", certUrl)}

    ord2, err := client.WaitOrder(ctx, certUrl)
    if err != nil {
		if ord2 != nil {certLib.PrintOrder(*ord2)}
		log.Fatalf("client.WaitOrder: %v\n",err)
	}
	log.Printf("received order!\n")

	if dbg {certLib.PrintOrder(*ord2)}

	for i:=0; i< numAcmeDom; i++ {

		csrData := csrList.Domains[i]
		//certLib.PrintCsr(csrData)
		domain := csrData.Domain
		log.Printf("generating certificate for domain: %s\n", domain)
		// get certificates
		certNam, err :=certLib.GenerateCertName(domain)
		if err != nil {log.Fatalf("GenerateCertName: %v", err)}

		keyFilnam := certDir + certNam + ".key"
		certFilnam := certDir + certNam + ".crt"
		log.Printf("key file: %s cert file: %s\n", keyFilnam, certFilnam)

		certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("GenerateKey: %v\n",err)
		}
		log.Printf("Cert Request: key generated!\n")

		err = certLib.SaveKeyPem(certKey, keyFilnam)
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
		log.Printf("Saving certificate to: %s", certFilnam)

		err = certLib.SaveCertsPem(derCerts, certFilnam)
        if err != nil {log.Fatalf("SaveCerts: %v\n",err)}

		// cleanup

		acmeZone := acmeDomList[i]

		err = cfApiObj.DelDnsChalRecord(acmeZone)
    	if err != nil {log.Fatalf("DelDnsChalRecord: %v\n",err)}
		log.Printf("deleted DNS Chal Record for zone: %s\n", acmeZone.Name)

	}

	log.Printf("success creating Certs\n")
}

