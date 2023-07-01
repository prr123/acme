// fetchCerts.go
// program that generates certificates from Lets encrypt using the DNS Challenge
// author: prr azul software
// date: 12 June 2023
// copyright 2023 prr, azulsoftware
//

package main

import (
	"context"

	"log"
	"fmt"
	"os"
//	"time"
//	"strings"
//	"golang.org/x/crypto/acme"

//    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)

    flags:=[]string{"dbg","csr","save"}

	// default file
	dbg := true
    csrFilnam := "csrTest.yaml"
	certNam := "testCert"
//	newOrder := &acme.Order{}

	useStr := "fetchCerts [/csr=csrfile] [/dbg] [/save=file]"
	helpStr := "program that retrieves all certs listed in csrList.yaml\n"

	if numarg > 4 {
		fmt.Println("too many arguments in cl!")
		fmt.Println("usage: %s\n", useStr)
		os.Exit(-1)
	}

	if numarg > 1 {
		if os.Args[1] == "help" {
			fmt.Printf("help:\n%s\n", helpStr)
			fmt.Printf("usage is: %s\n", useStr)
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

        val, ok = flagMap["save"]
        if !ok {
            log.Printf("default csrList: %s\n", csrFilnam)
        } else {
            if val.(string) == "none" {log.Fatalf("no yaml file provided with /save  flag!")}
            certNam = val.(string)
            log.Printf("cert Name: %s\n", certNam)
        }
	}

	certObj, err := certLib.InitCertLib()
	if err != nil {log.Fatalf("InitCertLib: %v\n", err)}
    if dbg {certLib.PrintCertObj(certObj)}

//	zoneFilnam := certObj.ZoneFilnam
//	cfApiFilnam := certObj.CfApiFilnam
	csrFilnam = certObj.CsrDir + csrFilnam

    certFilnam := certObj.CertDir + "/" + certNam + ".crt"

	log.Printf("debug: %t\n", dbg)
	log.Printf("Using csr file: %s\n", csrFilnam)
	log.Printf("Using cert file: %s\n", certFilnam)


	// read list of all domains for Acme Challenge
    csrList, err := certLib.ReadCsrFil(csrFilnam)
    if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	log.Printf("success reading CsrFile!\n")

	if dbg {certLib.PrintCsrList(csrList)}

	if len(csrList.CertUrl) == 0 {log.Fatalf("certUrl has no value!\n")}

	fmt.Printf("certUrl: %s\n", csrList.CertUrl)

    client, err := certLib.GetLEClient(csrList.AcntName, dbg)
    if err != nil {log.Fatalf("could not get Acme Client: certLib.GetLEAcnt: %v\n", err)}
    log.Printf("success obtaining Acme Client\n")

	derCerts, err := client.FetchCert(context.Background(), csrList.CertUrl, true)
    if dbg {log.Printf("derCerts: %d\n", len(derCerts))}

    // write the pem encoded certificate chain to file
    log.Printf("Saving certificate to: %s", certFilnam)

    err = certLib.SaveCertsPem(derCerts, certFilnam)
    if err != nil {log.Fatalf("SaveCerts: %v\n",err)}

	log.Printf("success saving Certs\n")
}
