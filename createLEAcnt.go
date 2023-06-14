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
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

    flags:=[]string{"dbg"}

	useStr := "creLEAcnt [/dbg]"
	helpStr := "help:\nprogram that creates a new account with Let's Encrypt CA\n"

	if numarg > 2 {
		fmt.Printf("usage: %s\n",useStr)
		fmt.Println("too many arguments in cl!")
		os.Exit(-1)
	}

	if numarg == 2 {
		if os.Args[1] == "help" {
			fmt.Println(helpStr)
			fmt.Printf("usage: %s\n",useStr)
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


	}

	log.Printf("debug: %t\n", dbg)

	leAcnt, err := certLib.CreateLEAccount()
	if err != nil {log.Fatalf("CreateLEAccount: %v\n", err)}
	log.Printf("success create account\n")

	if dbg {certLib.PrintLEAcnt(leAcnt)}

	client := leAcnt.Client
	dir, err := client.Discover(context.Background())
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success retrieving client dir from LE Acnt\n")
	if dbg {certLib.PrintDir(dir)}

}
