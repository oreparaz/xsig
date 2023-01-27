package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

func HelperVerifyData(msg []byte) (privateKey *ecdsa.PrivateKey, publicKeyBytes []byte, sig []byte){
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { panic(err) }

	hash := sha256.Sum256(msg)

	sig, err = ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil { panic(err) }

	pk := privateKey.PublicKey
	// 65 bytes always
	publicKeyBytes = elliptic.Marshal(pk.Curve, pk.X, pk.Y)

	return privateKey, publicKeyBytes, sig
}

