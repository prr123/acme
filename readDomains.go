// readDomains.go
// program that reads a yaml file containing domains for which we seek certificates
// Author: prr, azul software
// Date: 7 April 2023
// Copyright 2023 prr, azul software

package main

import (
	"fmt"
	"log"
	"os"
    yaml "github.com/goccy/go-yaml"
)

type acmeDns struct {
	File string
	Acme string `yaml:"acme"`
	Domains []string `yaml:"domains"`
}



func main() {

	useStr := "readDomains [domain file]\n"

	numArgs := len(os.Args)
	yamlFilNam := "acmeDomains.yaml"

	switch numArgs {
	case 0, 1:
		fmt.Println(useStr)
		os.Exit(0)
		// no domain file

	case 2, 3:

	default:
		fmt.Println(useStr)
		os.Exit(0)
	}

	acmeDom, err := rdDomain(yamlFilNam)
	if err != nil {log.Fatalf("rdDomain: %v\n", err)}

	PrintAcmeDom(acmeDom)
}

// function that reads the file with name filNam and returns an array of domain names
func rdDomain(filNam string) (acmeobj *acmeDns, err error) {

	var acmeDom acmeDns

	data, err := os.ReadFile(filNam)
	if err != nil {return nil, fmt.Errorf("os.ReadFile: %v", err)}

	acmeDom.File = filNam

	err = yaml.Unmarshal(data, &acmeDom)
    if err != nil { return nil, fmt.Errorf("yaml.Unmarshal: %v", err)}

	return &acmeDom, nil
}

func PrintAcmeDom(acmeDom *acmeDns) {

	fmt.Println("**********************************************")
	fmt.Printf("File: %s\n", acmeDom.File)
	fmt.Printf("acme: %s\n", acmeDom.Acme)
	fmt.Printf("domains: %d\n", len(acmeDom.Domains))
	for i:=0; i< len(acmeDom.Domains); i++ {
		fmt.Printf("domain[%d]: %s\n", i+1, acmeDom.Domains[i])
	}
	fmt.Println("**********************************************")
}
