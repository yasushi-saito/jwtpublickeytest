package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"time"

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
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
}

// Encode a public key in the PEM format.
func publicPEM(pubKey *ecdsa.PublicKey) []byte {
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(pubKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
}

func verify(pubPEM []byte, tokenStr string) {
	pubKey, err := jwt.ParseECPublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		log.Panic(err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			log.Panic("ValidateJWTToken: wrong signing method:", token)
		}
		return pubKey, nil
	})
	if err != nil {
		log.Panic(err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Panic("illegal claims: ", token)
	}
	log.Println("Claims: ", claims)
}

func sign(privPEM []byte, claims jwt.MapClaims) (tokenStr string) {
	privKey, err := jwt.ParseECPrivateKeyFromPEM(privPEM)
	if err != nil {
		log.Panic(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	tokenStr, err = token.SignedString(privKey)
	if err != nil {
		log.Panic(err)
	}
	return tokenStr
}

func main() {
	privKey := generatePrivateKey()
	privPEM := privatePEM(privKey)
	if err := ioutil.WriteFile("private.pem", privPEM, 0600); err != nil {
		log.Panic(err)
	}

	nowUTC := time.Now().In(time.UTC)
	expireUTC := nowUTC.Add(365 * 24 * time.Hour)
	claims := jwt.MapClaims{
		"sub": "foo@bar.com",
		"nbf": nowUTC.Add(-time.Minute).Unix(), // not before
		"exp": expireUTC.Unix(),
	}
	tokenStr := sign(privPEM, claims)
	log.Print("token:", tokenStr)
	pubPEM := publicPEM(&privKey.PublicKey)
	if err := ioutil.WriteFile("public.pem", pubPEM, 0600); err != nil {
		log.Panic(err)
	}
	if err := ioutil.WriteFile("claims.txt", []byte(tokenStr), 0600); err != nil {
		log.Panic(err)
	}
	verify(pubPEM, tokenStr)
}
