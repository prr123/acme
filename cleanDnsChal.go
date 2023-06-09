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
//	"context"
	"log"
	"fmt"
	"os"
	"net"
//	"time"
	"strings"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)
    dbg := true
    flags:=[]string{"dbg","csr"}

	useStr := "cleanSnsChal [/csr=csrfile] [/dbg]"
	helpStr := "program that expunges Dns challenge records and cleans up the csr file\n"

	csrFilnam := "csrTest.yaml"
	if numarg > 3 {
		fmt.Println(useStr)
		fmt.Println("too many arguments in cl!")
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

	certObj, err := certLib.InitCertLib()
    if err != nil {log.Fatalf("InitCertLib: %v\n", err)}
    if dbg {certLib.PrintCertObj(certObj)}

    csrFilnam = certObj.CsrDir + csrFilnam
	zoneFilnam:= certObj.ZoneDir + "/cfDomainsShort.yaml"
	cfApiFilnam := certObj.CfApiFilnam

	log.Printf("debug: %t\n", dbg)
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
    if err != nil {log.Fatalf("ReadCsrFil: %v\n", err)}
	log.Printf("success reading CsrFile!\n")

	numAcmeDom := len(csrList.Domains)
    log.Printf("found %d acme Domains\n", numAcmeDom)

	if dbg {certLib.PrintCsrList(csrList)}

	acmeDomList := make([]cfLib.ZoneAcme, numAcmeDom)
	// see whether acme domains are in zoneList

	count:=0
	for i:= 0; i< numAcmeDom; i++ {
		acmeDomNam := csrList.Domains[i].Domain
		for j:=0; j< numZones; j++ {
			if acmeDomNam == zoneList.Zones[j].Name {
				acmeDomList[i].Name = acmeDomNam
				acmeDomList[i].Id = zoneList.Zones[j].Id
				count++
				break
			}
		}
	}

	if count == 0 {log.Fatalf("no matching acme domains found in cf list!\n")}
	if count == numAcmeDom {
		log.Printf("all csr domains found in cd list!\n")
	} else {
		log.Printf("only %d out %d csr domains found in cd list!\n", count, numAcmeDom)
	}

	numAcmeDom = count
//    log.Printf("matched %d acme Domains\n", numAcmeDom)

	fmt.Println("*************************************")
	for j:= 0; j< numAcmeDom; j++ {
		log.Printf("domain[%d]: %-20s id: %s\n", j+1, acmeDomList[j].Name, acmeDomList[j].Id)
	}
	fmt.Println("*************************************")

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
			errStr := err.Error()
			idx := strings.Index(errStr, "127.0.0.53:53")
			if idx == -1 {
				log.Printf("domain %s: lookup error:%v\n", domain, err)
			} else {
				log.Printf("domain: %s -- no acme challenge record found!\n", domain)
			}
		}
	}

	if foundAcme == 0 {
		log.Printf("no residual Dns Challenge Records found!\n")
		err = certLib.CleanCsrFil(csrFilnam, csrList)
		if err != nil {log.Fatalf("cleanCsrFil: %v\n", err)}
		log.Printf("success clean-up acme Dns records!\n")
		os.Exit(1)
	}

	// clean-up Dns records
	log.Printf("found %d Domains with residual DNS Challenge records!\n", foundAcme)

	// get api for DNS use default yaml file
	apiObj, err := cfLib.InitCfApi(cfApiFilnam)
	if err != nil {log.Fatalf("cfLib.InitCfApi: %v\n", err)}
	log.Printf("success: init cfapi\n")

	for i:=0; i< numAcmeDom; i++ {
		if !acmeDomList[i].AcmeRec {continue}

		domain := acmeDomList[i].Name
		log.Printf("cleaning domain[%d]: %s\n", i+1, domain)

		zoneId := acmeDomList[i].Id
		dnsRecs, err := apiObj.ListDnsRecords(zoneId)
		if err != nil {log.Fatalf("domain[%d]: %s api.ListDNSRecords: %v\n", i+1, domain, err)}

		if dbg {cfLib.PrintDnsRecs(dnsRecs)}

		dnsId := ""
        for j:=0; j< len(*dnsRecs); j++ {
			idx := strings.Index((*dnsRecs)[j].Name, "_acme-challenge.")
            if idx == 0 {
                dnsId = (*dnsRecs)[j].ID
				log.Printf("found acme challenge record[%d] in domain %s\n", j+1, domain)
				err = apiObj.DelDnsRec(zoneId, dnsId)
				if err != nil {log.Fatalf("api.DeleteDNSRecord: %v\n", err)}
				log.Println("deleted Acme Dns Record")
			}
		}
	}

	log.Printf("finished cleaning acme dns records\n")
	err = certLib.CleanCsrFil(csrFilnam, csrList)
	if err != nil {log.Fatalf("cleanCsrFil: %v\n", err)}
	log.Printf("success clean-up acme Dns records!\n")
}

