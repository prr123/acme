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
)

func main() {

	useStr := "readCsrList csrfile"
	helpStr:= "program that reads a csrlist"

	numArg := len(os.Args)

	if numArg > 2 {
		fmt.Printf("usage is %s\n", useStr)
		log.Fatalf("too many cli args\n")
	}

//	if numArg < 2 {	}
	yamlFilnam := "csrList.yaml"
	if numArg == 2 {
		if os.Args[1] == "help" {
			fmt.Printf("usage is %s\n", useStr)
			fmt.Printf("help: \n%s\n",helpStr)
			os.Exit(1)
		}
		yamlFilnam = os.Args[1]
	}

	log.Printf("csrList Filnam: %s\n", yamlFilnam)

	csrList, err := certLib.ReadCsrFil(yamlFilnam)
	if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	
	certLib.PrintCsr(csrList)
	log.Printf("success readCsrList.go\n")
}

