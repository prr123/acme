// getAcnt.go
// program that generates Lets encrypt Account and saves keys
// author: prr azul software
// date: 8 May 2023
// copyright 2023 prr, azulsoftware
//

package main

import (
	"context"
	"crypto/ecdsa"
//	"crypto/elliptic"
//	"crypto/rand"
	"crypto/x509"
//    "crypto/x509/pkix"
//    "encoding/asn1"
    "encoding/pem"

	"log"
	"fmt"
	"os"
//	"time"
//	"net"
//	"strings"

//    yaml "github.com/goccy/go-yaml"
	"golang.org/x/crypto/acme"
//	"github.com/cloudflare/cloudflare-go"

//    cfLib "acme/acmeDns/cfLib"
	certLib "acme/acmeDns/certLib"
)


func main() {

	numarg := len(os.Args)
	dbg := true

	log.Printf("debug: %t\n", dbg)

	useStr := "getAcnt"

	certDir := "/home/peter/certDir/"

//	zoneFilNam := "/home/peter/zones/cfDomainsShort.yaml"
//	csrFilNam := "csrList.yaml"

	if numarg > 2 {
		fmt.Println(useStr)
		fmt.Println("too many arguments in cl!")
		os.Exit(-1)
	}

	if numarg == 2 {
		if os.Args[1] == "help" {
			fmt.Println(useStr)
			os.Exit(1)
		}
//		csrFilNam = os.Args[1]
	}

/*
	// get api for DNS use default yaml file
	cfapi, err := cfLib.InitCfApi("")
	if err != nil {log.Fatalf("cfLib.InitCfApi: %v\n", err)}
	log.Printf("success: init cfapi\n")


	log.Printf("Tested success: No old Acme Challenge Records found!")
*/

	// create new acme client
	// creating context
	ctx := context.Background()

	privfilNam := certDir + "LE_priv.key"
	pubfilNam := certDir + "LE_pub.key"

//	key := (client.Key).(*ecdsa.PrivateKey)
	akey, err := decodeKey(privfilNam, pubfilNam)
	if err != nil {log.Fatalf("decodeKey: %v\n", err)}

    client := &acme.Client{Key: akey}
    client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	acnt, err := client.GetReg(ctx, "")
	if err != nil {log.Fatalf("newClient: %v\n", err)}

	if dbg {certLib.PrintClient(client)}

	if dbg {certLib.PrintAccount(acnt)}

	dir, err := client.Discover(ctx)
	if err != nil {log.Fatalf("Discover error: %v\n", err)}

	log.Printf("success getting client dir\n")
	if dbg {certLib.PrintDir(dir)}
}

func encodeKey(privateKey *ecdsa.PrivateKey, filNam string) (err error) {

	var publicKey *ecdsa.PublicKey

	publicKey = &privateKey.PublicKey

	privKeyFilNam := filNam + "_priv.key"
	pubKeyFilNam := filNam + "_pub.key"

    x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {return fmt.Errorf("x509.MarshalECPrivateKey: %v", err)}

    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	err = os.WriteFile(privKeyFilNam, pemEncoded, 0644)
	if err != nil {return fmt.Errorf("pem priv key write file: %v", err)}

    x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {return fmt.Errorf("x509.MarshalPKIXPublicKey: %v", err)}

    pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	err = os.WriteFile(pubKeyFilNam, pemEncodedPub, 0644)
	if err != nil {return fmt.Errorf("pem pub key write file: %v", err)}

    return nil
}

func decodeKey(privFilNam, pubFilNam string) (key *ecdsa.PrivateKey, err error) {

	pemEncoded, err := os.ReadFile(privFilNam)
	if err != nil {return nil, fmt.Errorf("os.Read Priv Key: %v", err)}

	pemEncodedPub, err := os.ReadFile(pubFilNam)
	if err != nil {return nil, fmt.Errorf("os.Read Pub Key: %v", err)}

    block, _ := pem.Decode([]byte(pemEncoded))
    x509Encoded := block.Bytes
    privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {return nil, fmt.Errorf("x509.ParseECPivateKey: %v", err)}

    blockPub, _ := pem.Decode([]byte(pemEncodedPub))
    x509EncodedPub := blockPub.Bytes
    genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {return nil, fmt.Errorf("x509.ParsePKIXKey: %v", err)}

    publicKey := genericPublicKey.(*ecdsa.PublicKey)
	privateKey.PublicKey = *publicKey
    return privateKey, nil
}
