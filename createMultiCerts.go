// createMultiCerts.go
// program that generates certificates for each domain in the Csr File using Lets encrypt as the CA and tulizing the DNS Challenge
// author: prr azul software
// date: 31 March 2023
// copyright 2023 prr, azulsoftware
//
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

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true
	flags:=[]string{"dbg","csr"}

	useStr := "./createMultiCerts [/csr=csrfile][/dbg]"
    helpStr := "program that creates mutliple certificates, one for each of the domains listed in the file csrList.yaml\n"
    helpStr += "requirements: - a file listing all cloudflare domains/zones controlled by this account\n"
    helpStr += "              - a cloudflare authorisation file with a token that permits DNS record changes in the direcory cloudflare/token\n"
	helpStr += "              - a csr yaml file located in $LEAcnt/csrList\n"

	csrFilnam := "csrTest.yaml"

	if numarg > 4 {
		fmt.Println("too many arguments in cl!")
		fmt.Printf("usage: %s\n", useStr)
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
            log.Printf("using csrList: %s\n", csrFilnam)
        }
	}

	certObj, err := InitCertLib()
	if err != nil {log.Fatalf("InitCertLib: %v\n", certObj)
	if dbg {certLib.PrintCertObj(certObj)

	csrFilnam := certObj.LeAcnt + "csrList/" + csrFilnam
	log.Printf("Using csr file: %s\n", csrFilNam)

	// reading all domain names served by cloudflare
    zoneList, err := cfLib.ReadZoneShortFile(zoneFilNam)
    if err != nil {log.Fatalf("ReadZoneFileShort: %v\n", err)}
	if dbg {log.Printf("success reading all cf zones: %d!\n", len(zoneList))}
	if dbg {cfLib.PrintZoneList(zoneList)}

	numZones := len(zoneList.Zones)
	if numZones == 0 {log.Fatalf("no domains in file: %s\n", zoneFilNam)}

	// read list of all domains for Acme Challenge
    csrList, err := certLib.ReadCsrFil(csrFilNam)
    if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	if len(csrList.OrderUrl) > 0 {log.Fatalf("CsrLlist.OrderUrl is not empty!")
	if dbg {log.Printf("success reading CsrFile!\n")}

	numAcmeDom := len(csrList.Domains)
    if dbg {log.Printf("found %d acme Domains\n", numAcmeDom)}

	if dbg {certLib.PrintCsr(csrList)}
//	log.Printf("certDir: %s\n", csrList.CertDir)

	acmeDomList := make([]cfLib.ZoneAcme, numAcmeDom)
	// see whether acme domains are in zoneList

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

	ctx := context.Background()

    client, err := certLib.GetAcmeClient()
    if err != nil {log.Fatalf("could not get Acme Client: certLib.GetLEAcnt: %v\n", err)}
    log.Printf("success obtaining Acme Client\n")

    acnt, err := client.GetReg(ctx, "")
    if err != nil {log.Fatalf("could not find LE Client Account: getReg: %v\n", err)}
    if dbg {certLib.PrintAccount(acnt)}
    log.Printf("success retrieving LE Account\n")


	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(dir)}

	authIdList := make([]acme.AuthzID, 1)

	log.Printf("**** Begin Loop ****\n")
	for i:=0; i< numAcmeDom; i++ {
		authIdList[0].Type = "dns"
		authIdList[0].Value = acmeDomList[i].Name


		order, err := client.AuthorizeOrder(ctx, authIdList)
		if err != nil {log.Fatalf("client.AuthorizeOrder: %v\n",err)}

		log.Printf("received Authorization Order!\n")
		if dbg {certLib.PrintOrder(*order)}

		// acmeZone.Name and domain are the same..
		domain := authIdList[0].Value
		log.Printf("domain [%d]: %s\n", i+1, domain)

		url := order.AuthzURLs[0]
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
		tokVal, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {log.Fatalf("dns-01 token for %s: %v", domain, err)}
		log.Printf("success obtaining Dns token: %s\n", tokVal)

		recId, err := cfapi.AddDnsChalRecord(acmeZone, val)
		if err != nil {log.Fatalf("AddDnsChalRecord: %v", err)}
		acmeDomList[i].AcmeId = recId

        csrList.Domains[i].TokVal = tokVal
        csrList.Domains[i].Token = chal.Token
        csrList.Domains[i].TokUrl = chal.URI
        csrList.Domains[i].ChalRecId = recId
        csrList.Domains[i].TokIssue = time.Now()
        csrList.Domains[i].TokExp = auth.Expires
        csrList.Domains[i].OrderUrl = order.URI

        if dbg {
            zoneId := acmeDomList[i].Id
            dnsRecs, err := cfApiObj.ListDnsRecords(zoneId)
            if err != nil {log.Fatalf("domain[%d]: %s apiObj.ListDnsRecords: %v\n", i+1, acmeDomList[i].Name, err)}
            cfLib.PrintDnsRecs(dnsRecs)
        }

        csrList.Domains[i].TokVal = tokVal


        domain := csrList.Domains[i].Domain
        // check DNS Record via LookUp
        acmeDomain := "_acme-challenge." + domain

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

        if rdAttempt < 0 {
            log.Printf("domain: %s: could not look-up acme record!", domain)
            lookup = false
        } else {
            log.Printf("domain: %s: Lookup successful in %d attempts!\n", domain, rdAttempt +1)
        }
    }

    if !lookup {
        log.Printf("Could not lookup Acme Chal records for all domains!\n")
   		csrList.LastLU = time.Now()
    	err = certLib.WriteCsrFil(csrFilnam, csrList)
    	if err != nil {log.Fatal("certLib.WriteCsrFil: %v\n", err)}
        os.Exit(1)
    }



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

