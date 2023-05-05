// RdCsrList.go
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

	useStr := "Usage is: RdCsrList yaml_file"

	numArg := len(os.Args)

	if numArg > 2 {
		fmt.Println(useStr)
		log.Fatalf("too many cli args\n")
	}

	if numArg < 2 {
		fmt.Println(useStr)
		log.Fatalf("too few cli args\n")
	}

	yamlFilnam := os.Args[1]
	log.Printf("yamlFilnam: %s\n", yamlFilnam)

	csrList, err := certLib.ReadCsrFil(yamlFilnam)
	if err != nil {log.Fatalf("ReadCsrFil: %v", err)}
	
	certLib.PrintCsr(csrList)
	log.Printf("success RdCsrList.go\n")
}

