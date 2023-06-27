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

    util "github.com/prr123/utility/utilLib"
    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

    flags:=[]string{"dbg","csr"}
    csrFilnam := "csrTest.yaml"

	useStr := "./testDnsChal [/csr=csrfile] [/dbg]"
	helpStr := "program that tests propagation of Acme Dns records!"

//    cfApiFilnam := cfDir + "/token/cfDns.yaml"

	if numarg > 4 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg > 1 {
		if os.Args[1] == "help" {
			fmt.Printf("help: ")
			fmt.Printf("usage is: %s\n", useStr)
			fmt.Printf("\n%s\n", helpStr)
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


    zoneFilnam := certObj.ZoneFilnam
//    cfApiFilnam := certObj.CfApiFilnam
    csrFilnam = certObj.CsrDir + csrFilnam

    log.Printf("debug: %t\n", dbg)
    log.Printf("Using zone file: %s\n", zoneFilnam)
    log.Printf("Using csr file: %s\n", csrFilnam)

//    cfApiObj, err := cfLib.InitCfApi(cfApiFilnam)
//    if err != nil {log.Fatalf("cfLib.InitCfApi: %v\n", err)}
//    log.Printf("success: init cf api\n")

    // reading all domain names served by cloudflare
    zoneList, err := cfLib.ReadZoneShortFile(zoneFilnam)
    if err != nil {log.Fatalf("ReadZoneFileShort: %v\n", err)}
    if dbg {log.Printf("success reading all cf zones!\n")}
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

	if dbg {certLib.PrintCsrList(csrList)}

	acmeDomList := make([]cfLib.ZoneAcme, numAcmeDom)

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
//			log.Printf("*** errStr: %s\n", errStr)
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
