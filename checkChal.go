// checkChal.go
// program that performs a lookup to test the DNS Challenge propagation
// author: prr azul software
// date: 3 June 2023
// copyright 2023 prr, azulsoftware
//

package main

import (

	"log"
	"fmt"
	"os"
	"net"

//    yaml "github.com/goccy/go-yaml"
//	"golang.org/x/crypto/acme"
//	"github.com/cloudflare/cloudflare-go"

//    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "./checkChal [csrFile]"
	helpStr := "program that creates certs for all domains listed in the csr file. The default file is csrList.yaml\n"

/*
	zoneDir := os.Getenv("zoneDir")
	if len(zoneDir) == 0 {log.Fatalf("could not resolve env var zoneDir!")}

	certDir := os.Getenv("certDir")
	if len(certDir) == 0 {log.Fatalf("could not resolve env var certDir!")}

    zoneFilnam := zoneDir + "/cfDomainsShort.yaml"
*/


	csrFilnam := "csrList.yaml"

/*
    cfDir := os.Getenv("Cloudflare")
	if len(cfDir) == 0 {log.Fatalf("could not resolve env var cfDir!")}
    cfApiFilnam := cfDir + "/token/cfDns.yaml"
*/

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

//	log.Printf("Using zone file: %s\n", zoneFilnam)
	log.Printf("Using csr file: %s\n", csrFilnam)


	// read list of all domains for Acme Challenge
    csrList, err := certLib.ReadCsrFil(csrFilnam)
    if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	log.Printf("success reading CsrFile!\n")

	numAcmeDom := len(csrList.Domains)
    log.Printf("found %d acme Domains\n", numAcmeDom)

	if dbg {certLib.PrintCsr(csrList)}

	// search csrlist to chck for tokens
	missToken := false
    for i:=0; i< numAcmeDom; i++ {
		domain := csrList.Domains[i]
		if len(domain.Token) > 0 { continue }
		log.Printf("domain %s has no challenge token!", domain.Domain)
		missToken = true
	}
	if missToken {log.Fatalf("some domains do not have a challenge token!")}

	// test acme domains for challenge records
	log.Printf(" performing a look-up of acme records on all domains!")

	foundAcme := true
	for i:=0; i< numAcmeDom; i++ {
		domain := csrList.Domains[i]
		acmeDomain := "_acme-challenge." + domain.Domain

		log.Printf("domain %s: look-up for DNS Challenge Record!\n", domain.Domain)

		txtrecs, err := net.LookupTXT(acmeDomain)
		if err == nil {
			log.Printf("found acme challenge record!\n")
			if dbg {fmt.Printf("txtrecs [%d]: %s\n", len(txtrecs), txtrecs[0])}
		} else {
			log.Printf("no acme challenge record! %v", err)
			foundAcme = false
		}
	}

	if !foundAcme {log.Fatalf("some domains do not have acme challenge records!")}
	log.Printf("success: every domain has a acme challenge record!")
}

