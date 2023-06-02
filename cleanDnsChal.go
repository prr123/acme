// cleanDnsChal.go
// program that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 26 May 2023
// copyright 2023 prr, azulsoftware
//
// code copied to test
// may include some modifications made by the author to the original code
//

package main

import (
	"context"

	"log"
	"fmt"
	"os"
	"net"
	"strings"

//    yaml "github.com/goccy/go-yaml"
//	"golang.org/x/crypto/acme"
	"github.com/cloudflare/cloudflare-go"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "cleanSnsChal [domainfile]"

	zoneDir := os.Getenv("zoneDir")
	if len(zoneDir) < 1 {log.Fatalf("env Var zoneDir not found!\n")}
	log.Printf("found zoneDir: %s\n", zoneDir)
    zoneFilNam := zoneDir + "/cfDomainsShort.yaml"

	csrFilNam := "csrList.yaml"

	cfDir := os.Getenv("Cloudflare")
	if len(cfDir) < 1 {log.Fatalf("env Var Cloudflare not found!\n")}
	log.Printf("found Cloudflare: %s\n", cfDir)
    cfApiFilnam := cfDir + "/token/cfDns.yaml"



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

    // creating context
    ctx := context.Background()

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
    if err != nil {log.Fatalf("ReadCsrFil: %v\n", err)}
	log.Printf("success reading CsrFile!\n")

	numAcmeDom := len(csrList.Domains)
    log.Printf("found %d acme Domains\n", numAcmeDom)

	if dbg {certLib.PrintCsr(csrList)}

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
//    log.Printf("matched %d acme Domains\n", numAcmeDom)


	for j:= 0; j< numAcmeDom; j++ {
		log.Printf("acme domain [%d]: %-20s id: %s\n", j+1, acmeDomList[j].Name, acmeDomList[j].Id)
	}


	// test acme domains for challenge records
	foundAcme := 0
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
			foundAcme++
		} else {
			log.Printf("domain: %s -- no acme challenge record found!\n", domain)
		}
	}

	if foundAcme == 0 {
		log.Printf("no residual Dns Challenge Records found!\n")
		os.Exit(1)
	}

	log.Printf("found %d Domains with residual DNS Challenge records!\n", foundAcme)

	// get api for DNS use default yaml file
	cfapi, err := cfLib.InitCfApi(cfApiFilnam)
	if err != nil {log.Fatalf("cfLib.InitCfApi: %v\n", err)}
	log.Printf("success: init cfapi\n")

	// check acme target domains for left-over acme records
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

}
