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


	leobj, err := certLib.CreateNewLEAccount()
	if err != nil {log.Fatalf("CreateNewAccount: %v\n", err)}

	client := leobj.Client
	if leobj.Dbg {certLib.PrintAccount(leobj.Acnt)}

	ctx := context.Background()
	ledir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if leobj.Dbg {certLib.PrintDir(ledir)}

}

