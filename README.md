# acme
This repository contains acme test program(s) to test implementations of crypto/acme with a dns01 challenge.
The programs are based on the golang acme package, let's encrypt acting as the acme server and the CA, and the cloudflare API to change dns records. 

These programs also assume the following:  
1. There is a directory called LEAcnt and an environmental variable named LEAcnt which points to the folder LEAcnt.
2. There is a directory called zoneDir and an environmental variable named zoneDir wich points to that folder.
3. There is a directory called certDir and an environmental variable named certDir which points to the certdir.  

## zoneDir
This folder should contain a file named cfDomainsShort.yaml. The file contains the names and ids of all domains that are served with cloudflare's nameservers from your cloudflare account. The file content is generated by a the program [createDomainList]

## LEAcnt

This account contains (for now) the private and public key for the Let's Encrypt account. These keys are generated with the program 


## acme flow

### Step 1: Create CA Account

#### generate new account with CreLEAcnt

Program generates a private and public key (LE_private.key and LE_public.key). The key files are stored in the PEM format in the folder LEAcnt.  


### Step 2: Retrieve the CA Account and generate Acme Client  

GetLEAcnt retrieves the LE Account. This program can be used to check the existence of the LE Account.

The program, CreateCert, will retrieve the LE Account and generate an Acme client.  

### Step 3:  

### Step 4:

### Step 5:

### Step 6: 

## programs

### readCsrList
program that reads a CsrList yaml file

usage: ./RdCsrList csrList.yaml

### checkChal
program reads csrList File to check whether each domain has a DNS challenge record

### createCerts
program that creates ssl Certs

usage: ./createCerts csrList.yaml

### createCerts

#### Flow

1. read CsrList
2. read list of domains (zones) managed under cloudflare
3. create list of domains for certs
4. establish account with Lets Encrypt
5. from Let's Encrypt (LE) get authorisation order for the domain target list (step 3) for DNS challenge
6. for each domain:
   1. get authorization url
   2. get token
   3. add DNS text record to domain nameserver
   4. check by reading added Dns TXT record via lookup
   5. inform LE 
   6. confirm LE has validated challenge
   7. delete DNS text record from name server
   8. generate cert key and save as pem file in certDir
   9. generate CSR request
   10. submit CSR request to LE
   11. retrieve cert as bundle (cert chain) and save as pem file in certDir


## certLib
library that contains utility functions

### ReadCsrFil
function that reads the CSR file and returns a csrlist

### NewClient
generates a new acme client 

### RegisterClient
registers the client with Let's Encrypt and creates an LE account

### GenCertName
function that converts a domain name into name replacing periods with underscores

### SaveKeyPem
saves the private key in a file using the pem format

### SaveCertsPem
saves the certificate chain in a file using the pem format

### CreateCSRTpl 
create a CSR (Certificate Signing Request) template

### EncodeKey
converts a DER key into Pem byte slice

### DecodeKey
converts a Pem byte slice into a DER key

### saveAcmeClient
saves the private and public key of a client in PEM format

### getAcmeClient
reads the private and public keys from files and returns an acme client object

### PrintCSR
prints a CSR Object

### PrintAccount
prints an acme account object

### PrintJsAccount

### PrintClient
prints an acme client object

### PrintAuth
prints an acme authorisation object

### PrintDir
prints an acme directory object

### PrintOrder
prints an acme order object

### PrintChallenge
prints an acme challenge object

## acmeDnsTest
programs that tested part of the Dns Challenge

## Other

### csrTpl.yaml
yaml file template for the generation of ssl certificates.


dns provider is limited to cloudflare initially.

