package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
)

func VerifySignature(msg []byte, publicKeyBytes []byte, sig []byte) bool {
	hash := sha256.Sum256([]byte(msg))
	x,y :=  elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	pku := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return ecdsa.VerifyASN1(&pku, hash[:], sig)
}

