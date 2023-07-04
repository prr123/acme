// testCreCerts.go
// program that tests domains whether ns contains old acme challenge records
// author: prr azul software
// date: 8 May 2023
// copyright 2023 prr, azulsoftware
//

package main

import (
//	"context"
//	"crypto/ecdsa"
//	"crypto/elliptic"
//	"crypto/rand"
//	"crypto/x509"
//    "crypto/x509/pkix"
//    "encoding/asn1"
//    "encoding/pem"

	"log"
	"fmt"
	"os"
//	"time"
	"net"
//	"strings"

//    yaml "github.com/goccy/go-yaml"
//	"golang.org/x/crypto/acme"
//	"github.com/cloudflare/cloudflare-go"

    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "testCreCerts [domainfile]"
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

	if dbg {certLib.PrintCsrList(csrList)}
//	log.Printf("certDir: %s\n", csrList.CertDir)

	certDir := csrList.CertUrl
	certdir := []byte(csrList.CertUrl)
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
			log.Printf("no acme challenge record! %v", err)
		}
	}
	if foundAcme > 0{
		log.Printf("found %d domains with an acme chal record!\n", foundAcme)
	} else {
		log.Printf("success! found no domains with an acme chal record!\n")
	}
}
