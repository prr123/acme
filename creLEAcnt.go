// creLEAcnt.go
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

	useStr := "creLEAcnt"


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

	certDir, err := certLib.GetCertDir()
	if err != nil {log.Fatalf("GetCert: %v", err)}

	log.Printf("using certDir: %s\n", certDir)

	// todo remove old cert files

	// create new acme client
	// creating context
	ctx := context.Background()

	client, err := certLib.NewClient(ctx, dbg)
	if err != nil {log.Fatalf("newClient: %v\n", err)}

	log.Printf("success creating acme client!\n")
	if dbg {certLib.PrintClient(client)}

	filNam := certDir + "LE"


//	acnt, err := certLib.ReadAcmeAcnt(savActFilNam)
//	if err != nil {
	log.Printf("Creating Account\n")
	acnt, err := certLib.RegisterClient(ctx, client, dbg)
	if err != nil {log.Fatalf("registerClient: %v\n", err)}
	log.Printf("success registering client and creating account!")

	if dbg {certLib.PrintAccount(acnt)}

	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(dir)}

	err = certLib.SaveAcmeClient(client, filNam)
	if err != nil {log.Fatalf("SaceAcmeClient: %v\n", err)}

}

