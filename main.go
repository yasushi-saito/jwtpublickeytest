package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	generateRandomKeysFlag = flag.Bool("generate-random-keys", false,
		"Generate a random ECDSA private/public key pairs and store them in keys/*.pem")

	terraformFlag = flag.Bool("terraform", false,
		"Generate a random ECDSA private/public key pairs using terraform and store them in keys/*.pem.")
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
	flag.Parse()
	var privPEM, pubPEM []byte

	if *generateRandomKeysFlag {
		privKey := generatePrivateKey()
		privPEM = privatePEM(privKey)
		pubPEM = publicPEM(&privKey.PublicKey)
	} else {
		if !*terraformFlag {
			log.Panic("Exactly one of -generate-random-keys or -terraform must be set")
		}
		if err := exec.Command("terraform", "init").Run(); err != nil {
			log.Panic(err)
		}
		if err := exec.Command("terraform", "apply", "-auto-approve").Run(); err != nil {
			log.Panic(err)
		}
		out := bytes.Buffer{}
		cmd := exec.Command("terraform", "show", "-json")
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			log.Panic(err)
		}
		cmd = exec.Command("jq", ".values.root_module.resources[0].values")
		cmd.Stdin = &out
		jsout := bytes.Buffer{}
		cmd.Stdout = &jsout
		if err := cmd.Run(); err != nil {
			log.Panic(err)
		}
		var js struct {
			Algorithm     string `json:"algorithm"`
			ECSDACurve    string `json:"ecdsa_curve"`
			PrivateKeyPEM string `json:"private_key_pem"`
			PublicKeyPEM  string `json:"public_key_pem"`
		}
		if err := json.Unmarshal(jsout.Bytes(), &js); err != nil {
			log.Panic(err)
		}
		privPEM = []byte(js.PrivateKeyPEM)
		pubPEM = []byte(js.PublicKeyPEM)
	}

	if err := os.MkdirAll("keys", 0755); err != nil {
		log.Panic(err)
	}
	if err := ioutil.WriteFile("keys/private.pem", privPEM, 0600); err != nil {
		log.Panic(err)
	}
	if err := ioutil.WriteFile("keys/public.pem", pubPEM, 0600); err != nil {
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
	if err := ioutil.WriteFile("keys/claims.txt", []byte(tokenStr), 0600); err != nil {
		log.Panic(err)
	}
	verify(pubPEM, tokenStr)
}
