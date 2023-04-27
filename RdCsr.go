// RdCsr.go
// program that reads a yaml file and creates a certificate signing request
// Author: prr, azul software
// Date: 27 April 2023
// copyright: 2023 prr azul software
//

package main

import (
	"os"
	"fmt"
	"log"

	yaml "github.com/goccy/go-yaml"
)

type CsrDat struct {
	Template string `yaml:"template"`
	Domain string `yaml:"domain"`
	Email string `yaml:"email"`
	Name pkixName `yaml:"Name"`
}

type pkixName struct {
	CommonName string `yaml:"CommonName"`
	Country string `yaml:"Country"`
	Province string `yaml:"Province"`
	Locality string `yaml:"Locality"`
	Organisation string `yaml:"Organisation"`
	OrganisationUnit string `yaml:"OrganisationUnit"`
}

func main() {

	useStr := "Usage is: RdCsr yaml_file"

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

	bytData, err := os.ReadFile(yamlFilnam)
	if err != nil {
		log.Fatalf("os.ReadFile: %v\n",err)
	}

	CsrData := &CsrDat{}
	err = yaml.Unmarshal(bytData, CsrData)
	if err != nil {
		log.Fatalf("yaml Unmarshal: %v\n", err)
	}

	PrintCsr(CsrData)
	log.Printf("success RdCsr.go\n")
}

func PrintCsr(csrdat *CsrDat) {

	fmt.Println("******** Csr Data *********")
	fmt.Printf("template: %s\n", csrdat.Template)
	fmt.Printf("domain:   %s\n", csrdat.Domain)
	fmt.Printf("email:    %s\n", csrdat.Email)
	fmt.Printf("name:\n")
	nam:= csrdat.Name
	fmt.Printf("  CommonName:   %s\n", nam.CommonName)
	fmt.Printf("  Country:      %s\n", nam.Country)
	fmt.Printf("  Province:     %s\n", nam.Province)
	fmt.Printf("  Locality:     %s\n", nam.Locality)
	fmt.Printf("  Organisation: %s\n", nam.Organisation)
	fmt.Printf("  OrgUnit:      %s\n", nam.OrganisationUnit)
	fmt.Println("******** End Csr Data *******")

}
