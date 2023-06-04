// test AcmeProp.go
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
//	"context"

	"log"
	"fmt"
	"os"
//	"time"
	"net"
	"strings"

//    yaml "github.com/goccy/go-yaml"
//	"golang.org/x/crypto/acme"
//	"github.com/cloudflare/cloudflare-go"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

//	var order *acme.Order
//	var clientDir acme.Directory
//	var acnt *acme.Account

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "./testAcmeProp"
	helpStr := "program that tests propagation of Acme Dns records!"

	zoneDir := os.Getenv("zoneDir")
	if len(zoneDir) == 0 {log.Fatalf("could not resolve env var zoneDir!")}

	certDir := os.Getenv("certDir")
	if len(certDir) == 0 {log.Fatalf("could not resolve env var certDir!")}

    zoneFilnam := zoneDir + "/cfDomainsShort.yaml"

	csrFilnam := "csrList.yaml"

    cfDir := os.Getenv("Cloudflare")
	if len(cfDir) == 0 {log.Fatalf("could not resolve env var cfDir!")}

//    cfApiFilnam := cfDir + "/token/cfDns.yaml"

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

//	authIdList := make([]acme.AuthzID, numAcmeDom)

	if dbg {certLib.PrintCsr(csrList)}

	acmeDomList := make([]cfLib.ZoneAcme, numAcmeDom)
	// see whether acme domains are in zoneList

//	chalList := make([]acme.Challenge, numAcmeDom)

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

}
