package main

/* This code will produce a JWKS from any certificate supporte dby golang's standard crypto library
   It will give an error for any unsupported certificate types passed to it, but continue and use
   supported ones
*/

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-jose/go-jose"
)

func translateSignatureAlgorithm(SigAlg string, key interface{}) string {
	if SigAlg == "SHA256-RSA" {
		return "RS256"
	} else if SigAlg == "ECDSA-SHA256" {
		// For ECDSA, we need to determine the algorithm based on the curve
		if ecKey, ok := key.(*ecdsa.PublicKey); ok {
			switch ecKey.Curve.Params().BitSize {
			case 256:
				return "ES256"
			case 384:
				return "ES384"
			case 521:
				return "ES512"
			default:
				fmt.Println("[WARNING]Unsupported curve bit size:", ecKey.Curve.Params().BitSize, ", using default ES256")
				return "ES256"
			}
		}
		return "ES256" // Default if we can't determine the curve
	} else {
		fmt.Println("[WARNING]Unknown Signature Algorithm ", SigAlg, ", using default RS256")
		return "RS256"
	}
}

func main() {
	var jwks jose.JSONWebKeySet
	var jwk jose.JSONWebKey
	for _, certFile := range os.Args[1:] {
		//fmt.Println("Loading " + certFile)
		certBytes, err := os.ReadFile(certFile)
		if err != nil {
			fmt.Println("[FATAL]Unable to load "+certFile+": ", err)
			os.Exit(1)
		}
		var certs []*x509.Certificate
		var cert *x509.Certificate
		var block *pem.Block
		// read all the blocks from the file
		for len(certBytes) > 0 {
			block, certBytes = pem.Decode(certBytes)
			if block == nil {
				fmt.Println("[WARNING]No PEM data found in " + certFile)
				break
			}
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("[WARNING]Cannot parse "+certFile+", error: ", err)
				// Skip this certificate and continue with the next one
				break
			}
			certs = append(certs, cert)
		}

		// If no certificates were parsed, skip this file
		if len(certs) == 0 {
			fmt.Println("[WARNING]No valid certificates found in " + certFile + ", skipping")
			continue
		}

		// assuming the first one is the signing one.
		cert = certs[0]

		// Check if the public key is of a supported type
		switch cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			// ECDSA key, check if the curve is supported
			ecKey := cert.PublicKey.(*ecdsa.PublicKey)
			bitSize := ecKey.Curve.Params().BitSize
			if bitSize != 256 && bitSize != 384 && bitSize != 521 {
				fmt.Println("[WARNING]Unsupported curve bit size in "+certFile+": ", bitSize, ", skipping")
				continue
			}
		case *rsa.PublicKey:
			// RSA key, supported
		default:
			fmt.Println("[WARNING]Unsupported public key type in " + certFile + ", skipping")
			continue
		}

		sigAlg := translateSignatureAlgorithm(cert.SignatureAlgorithm.String(), cert.PublicKey)
		x5tSHA1 := sha1.Sum(cert.Raw)
		x5tSHA256 := sha256.Sum256(cert.Raw)
		jwk = jose.JSONWebKey{
			Key:                         cert.PublicKey,
			KeyID:                       cert.SerialNumber.String(),
			Algorithm:                   sigAlg,
			Certificates:                certs[:],
			CertificateThumbprintSHA1:   x5tSHA1[:],
			CertificateThumbprintSHA256: x5tSHA256[:],
			Use:                         "sig",
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}
	jsonJwks, err := json.Marshal(&jwks)
	if err != nil {
		fmt.Println("[FATAL]Unable to marshal JSON: ", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonJwks))
}
