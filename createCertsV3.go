// createCertsV3.go
// program that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 5 June 2023
// copyright 2023 prr, azulsoftware
//
// code copied from V2
// single order for multiple domains
//

package main

import (
	"context"

	"log"
	"fmt"
	"os"
	"time"
	"net"
	"strings"
	"golang.org/x/crypto/acme"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true
    flags:=[]string{"dbg","csr"}

	// default file
    csrFilnam := "csrTest.yaml"
	newOrder := &acme.Order{}

	useStr := "./createCertsV3 [/csr=csrfile] [/dbg]"
	helpStr := "program that creates one certificate for all domains listed in the file csrList.yaml\n"
	helpStr += "requirements: - a file listing all cloudflare domains/zones controlled by this account\n"
	helpStr += "              - a cloudflare authorisation file with a token that permits DNS record changes in the direcory cloudflare/token\n"
	helpStr += "              - a csr yaml file located in $LEAcnt/csrList\n"

	if numarg > 4 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg > 1 {
		if os.Args[1] == "help" {
			fmt.Printf("help:\n%s\n", helpStr)
			fmt.Printf("\nusage is: %s\n", useStr)
			os.Exit(1)
		}
        flagMap, err := util.ParseFlags(os.Args, flags)
        if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

        _, ok := flagMap["dbg"]
        if ok {dbg = true}
        if dbg {
            for k, v :=range flagMap {
                fmt.Printf("k: %s v: %s\n", k, v)
            }
        }

        val, ok := flagMap["csr"]
        if !ok {
            log.Printf("default csrList: %s\n", csrFilnam)
        } else {
            if val.(string) == "none" {log.Fatalf("no yaml file provided with /csr  flag!")}
            csrFilnam = val.(string)
            log.Printf("csrList: %s\n", csrFilnam)
        }
	}

	certObj, err := certLib.InitCertLib()
	if err != nil {log.Fatalf("InitCertLib: %v\n", err)}
    if dbg {certLib.PrintCertObj(certObj)}

	zoneFilnam := certObj.ZoneFilnam
	cfApiFilnam := certObj.CfApiFilnam
	csrFilnam = certObj.CsrDir + csrFilnam

	log.Printf("debug: %t\n", dbg)
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

	if dbg {certLib.PrintCsrList(csrList)}

	acmeDomList := make([]cfLib.ZoneAcme, numAcmeDom)
	// see whether acme domains are in zoneList

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

	newOrder, err = client.AuthorizeOrder(ctx, authIdList)
	if err != nil {log.Fatalf("client.AuthorizeOrder: %v\n",err)}
	log.Printf("received Authorization Order!\n")
	if dbg {certLib.PrintOrder(*newOrder)}

	log.Printf("**** Begin Loop ****\n")
	// need to loop through domains

	for i:=0; i< numAcmeDom; i++ {
		// acmeZone.Name and domain are the same..
		domain := authIdList[i].Value
		log.Printf("domain [%d]: %s\n", i+1, domain)

		url := newOrder.AuthzURLs[i]
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
	csrList.OrderUrl = newOrder.URI
	csrList.CertUrl = ""
	err = certLib.WriteCsrFil(csrFilnam, csrList)
	if err != nil {log.Fatal("certLib.WriteCsrFil: %v\n", err)}

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
	ordUrl := csrList.OrderUrl
	if len(ordUrl) == 0 {log.Fatalf("no order Url in CsrListFile!\n")}

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

		chal, err := client.Accept(ctx, &chalVal)
		if err != nil {log.Fatalf("dns-01 chal not accepted for %s: %v", domain, err)}
		if dbg {certLib.PrintChallenge(chal, domain)}
 		log.Printf("chal accepted for domain %s\n", domain)

	}

	tmpord, err := client.GetOrder(ctx, ordUrl)
	if err !=nil {log.Fatalf("order error: %v\n", err)}
	if dbg {certLib.PrintOrder(*tmpord)}

    log.Printf("waiting for order\n")
	if dbg {log.Printf("order url: %s\n", ordUrl)}

    ordUrl2, err := client.WaitOrder(ctx, ordUrl)
    if err != nil {
		if ordUrl2 != nil {certLib.PrintOrder(*ordUrl2)}
		log.Fatalf("client.WaitOrder: %v\n",err)
	}
	log.Printf("received order!\n")
	if dbg {certLib.PrintOrder(*ordUrl2)}

	csrData := csrList.Domains[0]

		//certLib.PrintCsr(csrData)
	domain := csrData.Domain
	log.Printf("generating certificate for domain: %s\n", domain)
		// get certificates
	certNam, err :=certLib.GenerateCertName(domain)
	if err != nil {log.Fatalf("GenerateCertName: %v", err)}
	if dbg {log.Printf("certNam: %s\n", certNam)}

	keyFilnam := certObj.CertDir + "/" + certNam + ".key"
	certFilnam := certObj.CertDir + "/" + certNam + ".crt"
	log.Printf("key file: %s cert file: %s\n", keyFilnam, certFilnam)

//	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certKey, err := certLib.GenCertKey()
	if err != nil {
		log.Fatalf("GenCertKey: %v\n",err)
	}
	log.Printf("Cert Request: key generated!\n")

	err = certLib.SaveKeyPem(certKey, keyFilnam)
	if err != nil {log.Fatalf("certLib.SaveKeypem: %v",err)}
	log.Printf("Save: key saved as PEM!\n")

	csrTpl, err := certLib.CreateCsrTplNew(csrList, -1)
	if err != nil {	log.Fatalf("CreateCsrTpl: %v",err)}

//	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTpl, certKey)
//	if err != nil {	log.Fatalf("CreateCertReq: %v",err)}

	csr, err := certLib.CreateCsr(csrTpl, certKey)
	if err != nil {	log.Fatalf("CreateCertReq: %v",err)}

	csrParseReq, err := certLib.ParseCsr(csr)
	if err != nil {log.Fatalf("Error parsing certificate request: %v", err)}

	// need to compare csrParse and template
	certLib.PrintCsrReq(csrParseReq)

	FinalUrl := ordUrl2.FinalizeURL
	log.Printf("FinalUrl: %s\n", FinalUrl)

	derCerts, certUrl, err := client.CreateOrderCert(ctx, FinalUrl, csr, true)
	if err != nil {log.Fatalf("CreateOrderCert: %v\n",err)}

	if dbg {log.Printf("derCerts: %d certUrl: %s\n", len(derCerts), certUrl)}

	csrList.CertUrl = certUrl
	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s", certFilnam)

	err = certLib.SaveCertsPem(derCerts, certFilnam)
	if err != nil {log.Fatalf("SaveCerts: %v\n",err)}

	// cleanup
	for i:=0; i< numAcmeDom; i++ {
		acmeZone := acmeDomList[i]
		acmeZone.AcmeId = csrList.Domains[i].ChalRecId

		err = cfApiObj.DelDnsChalRecord(acmeZone)
    	if err != nil {log.Fatalf("DelDnsChalRecord: %v\n",err)}
		log.Printf("deleted DNS Chal Record for zone: %s\n", acmeZone.Name)
	}

	if dbg {certLib.PrintCsrList(csrList) }
	err = certLib.CleanCsrFil(csrFilnam, csrList)
	if err != nil {log.Fatalf("CleanCsrFil: %v\n",err)}
	log.Printf("success writing Csr File\n")

	log.Printf("success creating Certs\n")
}

