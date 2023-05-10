# acme
folder contains acme test program(s) to test implementations of crypto/acme with a dns01 challenge.

## programs

### RdCsrList
program that reads a CsrList yaml file

usage: ./RdCsrList csrList.yaml

### createCerts
program that creates ssl Certs

usage: ./createCerts csrList.yaml

#### Flow

1. read CsrList
2. read list of domains (zones) managed under cloudflare
3. create list of domains for certs
4. establish account with Lets Encrypt
5. from LE get authorisation order for the domain target list (step 3) for DNS challenge
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

