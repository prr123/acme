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

	
//	if numArg < 2 {	}


	leAcnt := os.Getenv("LEAcnt")
	if len(leAcnt) < 1 {
		log.Fatalf("cannot find envVar LEAcnt\n")
	}
	csrDirnam := leAcnt + "/csrList"
	yamlFilnam := csrDirnam + "/csrTest.yaml"
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
			log.Printf("default csrList: %s\n", yamlFilnam)
		} else {
			if val.(string) == "none" {log.Fatalf("no yaml file provided with /csr  flag!")}
			yamlFilnam = csrDirnam + "/" + val.(string)
			log.Printf("using csrList: %s\n", yamlFilnam)
		}

	}

	log.Printf("dbg: %t\n", dbg)

//	os.Exit(1)

	csrList, err := certLib.ReadCsrFil(yamlFilnam)
	if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	
	certLib.PrintCsr(csrList)
	log.Printf("success readCsrList.go\n")
}

