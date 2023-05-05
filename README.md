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
6.1 get authorization url
6.2 get token
6.3 add DNS text record to domain nameserver
6.4 check by reading added Dns TXT record via lookup
6.5 inform LE 
6.6 confirm LE has validated challenge
6.7 delete DNS text record from name server
6.8 generate cert key and save as pem file in certDir
6.9 generate CSR request
6.10 submit CSR request to LE
6.11 retrieve cert as bundle (cert chain) and save as pem file in certDir


### certLib
library that contains utility functions


### acmeDnsTest
programs that tested part of the Dns Challenge

## Other

## csrTpl.yaml
yaml file template for the generation of ssl certificates.



dns provider is limited to cloudflare initially.

