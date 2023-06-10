// checkAcnt.go
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

	useStr := "getAcnt"

	fmt.Printf("numarg: %d\n", numarg)
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

	client, err := certLib.GetAcmeClient()
	if err != nil {log.Fatalf("certLib.GetAcmeClient: %v\n", err)}

	acnt, err := client.GetReg(ctx, "")
	if err != nil {log.Fatalf("newClient: %v\n", err)}
	log.Printf("Retrieved Acnt!\n")

	if dbg {certLib.PrintClient(client)}

	if dbg {certLib.PrintAccount(acnt)}

	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(dir)}
}
