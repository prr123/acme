// creAcnt.go
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
//	"time"

	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "creLEAcnt"
	helpStr := "help:\nprogram that creates an account with Let's Encrypt\n"

	if numarg > 2 {
		fmt.Println(useStr)
		fmt.Println("too many arguments in cl!")
		os.Exit(-1)
	}

	if numarg == 2 {
		if os.Args[1] == "help" {
			fmt.Println(helpStr)
			fmt.Println(useStr)
			os.Exit(1)
		}
		log.Printf("invalid argument!\n")
		os.Exit(1)
	}

	leAcnt, err := certLib.CreateLEAccount()
	if err != nil {log.Fatalf("CreateLEAccount: %v\n", err)}


	if leAcnt.Dbg {certLib.PrintLEAcnt(leAcnt)}

	client := leAcnt.Client
	dir, err := client.Discover(context.Background())
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(dir)}

}
