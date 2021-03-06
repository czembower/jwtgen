# jwtgen

## Table of Contents

1. [Description](#description)
1. [Usage](#usage)
1. [Limitations](#limitations)
1. [References](#references)

## Description

A command-line utility to create signed and encrypted JWT tokens with support for private claims. \
Utilizes the fantastic go-jose library from Square: https://github.com/square/go-jose \
\
A public key pem file (`public.pem`), encryption key (`.sek`), and JWT token (`token`) are generated and exported to the filesystem path specified by the ```--outdir``` parameter.

## Usage

```git clone https://github.com/czembower/jwtgen.git && cd jwtgen && go get -d ./... && go build```\
```./jwtgen [args]```

jwtgen arguments:
*  `-audience` \[string\]
    	jwt token audience (default "audience")
* ` -id` \[string\]
    	jwt token id (default "identifier")
*  `-issuer` \[string\]
    	jwt token issuer (default "issuer")
*  `-outdir` \[string\]
    	output directory to render assets (default "./output/")
*  `-privateClaims` \[string\]
    	comma separated list of private claims in key=value format
* `-subject` \[string\]
    	jwt token subject (default "subject")
* ` -ttl` \[string\]
    	ttl of token in seconds (default "86400")

## Limitations

The RSA keypair can not currently be imported or specified, as it is generated by the utility at run time.

## References
https://medium.com/@niceoneallround/jwts-in-go-golang-4e0151f899af