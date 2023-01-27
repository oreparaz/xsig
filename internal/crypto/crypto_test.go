package crypto

import (
	"crypto/ecdsa"
	"github.com/stretchr/testify/assert"
	"testing"
)

var privKey *ecdsa.PrivateKey

func TestVerifySignature(t *testing.T) {
	msg := []byte("hello, world")
	for i := 0; i<100; i++ {
		_, publicKeyBytes, sig :=  HelperVerifyData(msg)
		assert.True(t, VerifySignature(msg, publicKeyBytes, sig))
	}
}
