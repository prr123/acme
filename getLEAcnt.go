// getAcnt.go
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

	certDir := "/home/peter/certDir/"

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

	privfilNam := certDir + "LE_priv.key"
	pubfilNam := certDir + "LE_pub.key"

	client, err := certLib.GetAcmeClient(privfilNam, pubfilNam)
	if err != nil {log.Fatalf("certLib.GetLEAcnt: %v\n", err)}

	acnt, err := client.GetReg(ctx, "")
	if err != nil {log.Fatalf("newClient: %v\n", err)}

	if dbg {certLib.PrintClient(client)}

	if dbg {certLib.PrintAccount(acnt)}

	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(dir)}
}
