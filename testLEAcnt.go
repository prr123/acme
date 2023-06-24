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
    util "github.com/prr123/utility/utilLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)
    flags:=[]string{"dbg", "acnt"}
    acntFil := "LEAcnt.yaml"

    useStr := "testLEAcnt [/acnt=file] [/dbg]"
    helpStr := "help:\nprogram that reads a account file with Let's Encrypt CA\n"

	if numarg > 3 {
		fmt.Printf("usage: %s\n",useStr)
		fmt.Println("too many arguments in cl!")
		os.Exit(-1)
	}

	if numarg > 1{
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
				fmt.Printf("flag: %s value: %s\n", k, v)
			}
		}
        val, ok := flagMap["acnt"]
        if ok {
            acntFil = val.(string)
        }


	}

	// creating context
	ctx := context.Background()

	client, err := certLib.GetLEClient(acntFil, true)
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

