// readCsrList.go
// program that reads a yaml file and creates a certificate signing request list
// Author: prr, azul software
// Date: 27 April 2023
// copyright: 2023 prr azul software
//

package main

import (
	"os"
	"fmt"
	"log"
	"context"

	certLib "acme/acmeDns/certLib"
    util "github.com/prr123/utility/utilLib"
)

func main() {

	useStr := "readCsrList [/csr] [/dbg]"
	helpStr:= "program that reads a csrlist"

    flags:=[]string{"dbg","csr"}

	numArg := len(os.Args)

	if numArg > 3 {
		fmt.Printf("usage is %s\n", useStr)
		log.Fatalf("too many cli args\n")
	}

    csrFilnam := "csrTest.yaml"
	dbg := false

	if numArg > 1 {
		if os.Args[1] == "help" {
			fmt.Printf("usage is %s\n", useStr)
			fmt.Printf("help: \n%s\n",helpStr)
			os.Exit(1)
		}
		flagMap, err := util.ParseFlags(os.Args, flags)
		if err != nil {log.Fatalf("util.ParseFlags: %v\n", err)}

		if dbg {
	    	for k, v :=range flagMap {
    	    	fmt.Printf("k: %s v: %s\n", k, v)
    		}
		}
		_, ok := flagMap["dbg"]
		if ok {dbg = true}

		val, ok := flagMap["csr"]
		if !ok {
			log.Printf("default csrList: %s\n", csrFilnam)
		} else {
			if val.(string) == "none" {log.Fatalf("no yaml file provided with /csr  flag!")}
            csrFilnam = val.(string)
            log.Printf("csrList: %s\n", csrFilnam)
		}

	}

    certObj, err := certLib.InitCertLib()
    if err != nil {log.Fatalf("InitCertLib: %v\n", err)}
    if dbg {certLib.PrintCertObj(certObj)}

    csrFilnam = certObj.CsrDir + csrFilnam

	log.Printf("dbg: %t\n", dbg)
	log.Printf("Using csr file: %s\n", csrFilnam)

	csrList, err := certLib.ReadCsrFil(csrFilnam)
	if err != nil {log.Fatalf("ReadCsrFil: %v", err)}

	certLib.PrintCsrList(csrList)
	log.Printf("success reading readCsrList.go\n")

	acntNam := csrList.AcntName
	log.Printf("testing account file with name: %s!\n", acntNam)

	ctx := context.Background()

    client, err := certLib.GetLEClient(acntNam, true)
    if err != nil {log.Fatalf("getLEClient: %v\n", err)}

//    certLib.PrintClient(client)

    ledir, err := client.Discover(ctx)
    if err != nil {log.Fatalf("Discover error: %v\n", err)}
    log.Printf("success getting client dir\n")
    certLib.PrintDir(ledir)

    acnt, err := client.GetReg(ctx, "")
    if err != nil {log.Fatalf("could not find LE Client Account: getReg: %v\n", err)}
    if dbg {certLib.PrintAccount(acnt)}
    log.Printf("success retrieving LE Account\n")
}

