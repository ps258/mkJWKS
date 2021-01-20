package main

import (
  "crypto/sha1"
  "crypto/sha256"
  "crypto/x509"
  "encoding/json"
  "encoding/pem"
  "fmt"
  "io/ioutil"
  "os"
  "github.com/go-jose/go-jose"
)

func translateSignatureAlgorithm(SigAlg string) (string) {
  if SigAlg == "SHA256-RSA" {
    return "RS256"
  } else if SigAlg == "ECDSA-SHA256" {
    return "ES256"
  } else {
    fmt.Println("[FATAL]Unknown Signature Algorithm ", SigAlg)
    os.Exit(1)
  }
  return ""
}

func main() {
  var jwks jose.JSONWebKeySet
  var jwk jose.JSONWebKey
  for _, certFile := range os.Args[1:] {
    //fmt.Println("Loading " + certFile)
    certBytes, err := ioutil.ReadFile(certFile)
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
      cert, err = x509.ParseCertificate(block.Bytes)
      if err != nil {
        fmt.Println("[FATAL]Cannot parse "+certFile+", error: ", err)
        os.Exit(1)
      }
      certs = append(certs, cert)
    }
    // assuming the first one is the signing one.
    cert = certs[0]
    sigAlg := translateSignatureAlgorithm(cert.SignatureAlgorithm.String())
    x5tSHA1 := sha1.Sum(cert.Raw)
    x5tSHA256 := sha256.Sum256(cert.Raw)
    jwk = jose.JSONWebKey {
      Key: cert.PublicKey,
      KeyID: cert.SerialNumber.String(),
      Algorithm: sigAlg,
      Certificates: certs[:],
      CertificateThumbprintSHA1: x5tSHA1[:],
      CertificateThumbprintSHA256: x5tSHA256[:],
      Use: "sig",
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
