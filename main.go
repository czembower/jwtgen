// Repository: github.com/czembower/jwtgen
// Copyright 2021 Chris Zembower
// Author: Chris Zembower
// Email: czembower@gmail.com
// License: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	mathrand "math/rand"
	"os"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func genKeyPair(outdir string) (*rsa.PrivateKey, *rsa.PublicKey) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(outdir + "public.pem")
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}

	return privatekey, publickey
}

func mustMakeSigner(alg jose.SignatureAlgorithm, k interface{}) jose.Signer {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, nil)
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	return sig
}

func generateSharedKey(n int) string {
	mathrand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[mathrand.Intn(len(letterRunes))]
	}
	return string(b)
}

func createToken() {
	var (
		issuer        string
		subject       string
		audience      string
		id            string
		outdir        string
		ttl           string
		privateClaims string
	)

	flag.StringVar(&issuer, "issuer", "issuer", "jwt token issuer")
	flag.StringVar(&subject, "subject", "subject", "jwt token subject")
	flag.StringVar(&audience, "audience", "audience", "jwt token audience")
	flag.StringVar(&id, "id", "identifier", "jwt token id")
	flag.StringVar(&outdir, "outdir", "./", "output directory to render assets")
	flag.StringVar(&ttl, "ttl", "86400", "ttl of token in seconds")
	flag.StringVar(&privateClaims, "privateClaims", "", "comma separated list of private claims in key=value format")
	flag.Parse()

	if !strings.HasSuffix(outdir, "/") {
		outdir = outdir + "/"
	}

	if !strings.HasSuffix(ttl, "s") {
		ttl = ttl + "s"
	}

	expire, _ := time.ParseDuration(ttl)

	os.MkdirAll(outdir, 0755)
	rsaPrivKey, _ := genKeyPair(outdir)

	sharedKey := generateSharedKey(16)
	var sharedEncryptionKey = []byte(sharedKey)
	var rsaSigner = mustMakeSigner(jose.RS256, rsaPrivKey)
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       sharedEncryptionKey,
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		panic(err)
	}

	nowTime := time.Now().UTC()

	cl := jwt.Claims{
		Subject:   subject,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(nowTime),
		NotBefore: jwt.NewNumericDate(nowTime),
		Expiry:    jwt.NewNumericDate(nowTime.Add(time.Second * time.Duration(expire.Seconds()))),
		Audience:  jwt.Audience{audience},
		ID:        id,
	}

	if privateClaims != "" {
		privateClaimsList := strings.Split(privateClaims, ",")
		pcl := make(map[string]interface{}, len(privateClaimsList))
		for i := 0; i < len(privateClaimsList); i++ {
			index := strings.Split(privateClaimsList[i], "=")[0]
			value := strings.Split(privateClaimsList[i], "=")[1]
			pcl[index] = value
		}
		raw, err := jwt.SignedAndEncrypted(rsaSigner, enc).Claims(cl).Claims(pcl).CompactSerialize()
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile(outdir+"token", []byte(raw), 0755)
		ioutil.WriteFile(outdir+".sek", sharedEncryptionKey, 0755)
	} else {
		raw, err := jwt.SignedAndEncrypted(rsaSigner, enc).Claims(cl).CompactSerialize()
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile(outdir+"token", []byte(raw), 0755)
		ioutil.WriteFile(outdir+".sek", sharedEncryptionKey, 0755)
	}

}

func main() {
	createToken()
}
