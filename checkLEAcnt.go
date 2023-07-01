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

    util "github.com/prr123/utility/utilLib"
	certLib "acme/acmeDns/certLib"
    yaml "github.com/goccy/go-yaml"
)


func main() {

	numarg := len(os.Args)
	dbg := false
	acntNam := "LEAcnt"

	log.Printf("debug: %t\n", dbg)

	useStr := "checkLEAcnt [/acnt=name] [/dbg]"

//	fmt.Printf("numarg: %d\n", numarg)
	if numarg > 3 {
		fmt.Println(useStr)
		fmt.Println("too many arguments in cl!")
		os.Exit(-1)
	}

	if numarg >1 && os.Args[1] == "help" {
		fmt.Println(useStr)
		os.Exit(1)
	}

    flags:=[]string{"dbg","acnt"}
    flagMap, err := util.ParseFlags(os.Args, flags)
    if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

    _, ok := flagMap["dbg"]
    if ok {dbg = true}
    if dbg {
        for k, v :=range flagMap {
            fmt.Printf("flag: /%s value: %s\n", k, v)
        }
    }

    val, ok := flagMap["acnt"]
    if ok {
        if val.(string) == "none" {log.Fatalf("no account name provided with /acnt  flag!")}
        acntNam = val.(string)
        log.Printf("using account: %s\n", acntNam)
    } else {
        log.Printf("default account: %s\n", acntNam)
    }

	log.Printf("checking client for account: %s\n", acntNam)

	LEDir, err  := certLib.GetCertDir(acntNam)
    if err != nil {log.Fatalf("getCertDir: %v\n", err)}

    acntFilnam := LEDir + acntNam + ".yaml"
    acntData, err := os.ReadFile(acntFilnam)
    if err != nil {log.Fatalf("reading account File: %s! %v", acntFilnam, err)}

    leAcnt := certLib.LEObj{}

    err = yaml.Unmarshal(acntData, &leAcnt)
    if err != nil {log.Fatalf("yaml Unmarshal account file: %v\n", err)}

	if leAcnt.AcntNam != acntNam {log.Fatalf("acount names do not match")}
//    if len(leAcnt.AcntName) < 1 {return nil, fmt.Errorf("no AcntName provided!\n")}

	certLib.PrintLEAcnt(&leAcnt)

	// creating context
	ctx := context.Background()

	client, err := certLib.GetAcmeClient(acntNam)
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
