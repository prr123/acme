// testClient.go
// program that generates Lets encrypt Account and saves keys
// author: prr azul software
// date: 8 May 2023
// copyright 2023 prr, azulsoftware
//

package main

import (
	"context"

	"log"
	"fmt"
	"os"

	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "testAcnt"

//	zoneFilNam := "/home/peter/zones/cfDomainsShort.yaml"
//	csrFilNam := "csrList.yaml"

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
	}

	// creating context
	ctx := context.Background()

	client, err := certLib.GetLEClient()
	if err != nil {log.Fatalf("getLEClient: %v\n", err)}

	certLib.PrintClient(client)

	ledir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}
	log.Printf("success getting client dir\n")
	certLib.PrintDir(ledir)

    acnt, err := client.GetReg(ctx, "")
    if err != nil {log.Fatalf("could not find LE Client Account: getReg: %v\n", err)}
    if dbg {certLib.PrintAccount(acnt)}
    log.Printf("success retrieving LE Account\n")
}

