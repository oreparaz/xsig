package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	ll "github.com/oreparaz/xsig/internal/lowlevel"
	"github.com/oreparaz/xsig/pkg"
	"log"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, []byte) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return pemEncoded, pemEncodedPub
}

func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}

func keygen() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return privateKey, &privateKey.PublicKey
}

func main() {
	// part 1: keygen
	priv1, pub1 := keygen()
	priv2, pub2 := keygen()
	priv3, pub3 := keygen()

	priv1_s, pub1_s := encode(priv1, pub1)
	priv2_s, pub2_s := encode(priv2, pub2)
	priv3_s, pub3_s := encode(priv3, pub3)

	err := os.WriteFile("private1.pem", priv1_s, 0644); check(err)
	err  = os.WriteFile("private2.pem", priv2_s, 0644); check(err)
	err  = os.WriteFile("private3.pem", priv3_s, 0644); check(err)
	err  = os.WriteFile("public1.pem", pub1_s, 0644); check(err)
	err  = os.WriteFile("public2.pem", pub2_s, 0644); check(err)
	err  = os.WriteFile("public3.pem", pub3_s, 0644); check(err)

	pk1Bytes := elliptic.Marshal(pub1.Curve, pub1.X, pub1.Y)
	pk2Bytes := elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y)
	pk3Bytes := elliptic.Marshal(pub3.Curve, pub3.X, pub3.Y)

	// part 2: create the lock script / xPublickey for a 2-of-3 multisig
	xPublicKey := ll.Assembler{}
	xPublicKey.Append(ll.Push(pk1Bytes))
	xPublicKey.Append(ll.Push(pk2Bytes))
	xPublicKey.Append(ll.Push(pk3Bytes))
	xPublicKey.Append(ll.Push1(2))
	xPublicKey.Append(ll.Push1(3))
	xPublicKey.Append(ll.MultisigVerify())
	xPublicKeyCode := xPublicKey.Code

	log.Printf("xpublickey: %x\n", xPublicKeyCode)

	// part 3: sign
	msg := []byte("yo")
	hash := sha256.Sum256(msg)
	sig1, err := ecdsa.SignASN1(rand.Reader, priv1, hash[:]); check(err)
	sig2, err := ecdsa.SignASN1(rand.Reader, priv2, hash[:]); check(err)
	sig3, err := ecdsa.SignASN1(rand.Reader, priv3, hash[:]); check(err)

	// part 4: craft the unlock script / xSignature
	a := ll.Assembler{}
	a.Append(ll.Push(sig1))
	a.Append(ll.Push(sig2))
	_ = sig3

	xSignatureCode := a.Code

	log.Printf("xsignature: %x\n", xSignatureCode)

	// part 4: verify
	if pkg.EvaluateXSig(xPublicKeyCode, xSignatureCode, msg) {
		log.Printf("validates correctly")
	} else {
		log.Fatalf("does not validate")
	}
}
