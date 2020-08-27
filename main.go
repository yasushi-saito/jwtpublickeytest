package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"

	"github.com/dgrijalva/jwt-go"
)

func generatePrivateKey() *ecdsa.PrivateKey {
	curve := elliptic.P384()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	return privKey
}

// Encode a private key in the PEM format.
func privatePEM(privKey *ecdsa.PrivateKey) []byte {
	x509Encoded, _ := x509.MarshalECPrivateKey(privKey)
	return pem.EncodeToMemory(&pem.Block{Type: "EC384 PRIVATE KEY", Bytes: x509Encoded})
}

// Encode a public key in the PEM format.
func publicPEM(pubKey *ecdsa.PublicKey) []byte {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(pubKey)
	return pem.EncodeToMemory(&pem.Block{Type: "EC384 PUBLIC KEY", Bytes: x509EncodedPub})
}

func verify(pubPEM []byte, data, sig string) {
	pubKey, err := jwt.ParseECPublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		log.Panic(err)
	}
	method := jwt.GetSigningMethod("ES384")
	err = method.Verify(data, sig, pubKey)
	if err != nil {
		log.Panic(err)
	}
}

func sign(privPEM []byte, data string) (sig string) {
	privKey, err := jwt.ParseECPrivateKeyFromPEM(privPEM)
	if err != nil {
		log.Panic(err)
	}
	method := jwt.GetSigningMethod("ES384")
	sig, err = method.Sign(data, privKey)
	if err != nil {
		log.Panic(err)
	}
	return sig
}

func main() {
	privKey := generatePrivateKey()
	privPEM := privatePEM(privKey)
	const data = "foohah"
	sig := sign(privPEM, data)

	pubPEM := publicPEM(&privKey.PublicKey)
	verify(pubPEM, data, sig)
}
