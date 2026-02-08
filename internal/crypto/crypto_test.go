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
		_, publicKeyBytes, sig := HelperVerifyData(msg)
		assert.True(t, VerifySignature(msg, publicKeyBytes, sig))
	}
}

func TestVerifySignature_InvalidCurvePoint(t *testing.T) {
	// A compressed key with valid 0x02 prefix but an X coordinate that
	// doesn't correspond to a point on P256. UnmarshalCompressed returns
	// nil,nil for such points. VerifySignature must not panic.
	invalidPK := make([]byte, 33)
	invalidPK[0] = 0x02
	for i := 1; i < 33; i++ {
		invalidPK[i] = 0xFF
	}
	dummySig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	assert.False(t, VerifySignature([]byte("test"), invalidPK, dummySig))
}

func TestVerifySignature_WrongMessage(t *testing.T) {
	msg := []byte("correct message")
	_, pk, sig := HelperVerifyData(msg)
	assert.False(t, VerifySignature([]byte("wrong message"), pk, sig))
}

func TestVerifySignature_CorruptedSignature(t *testing.T) {
	msg := []byte("hello")
	_, pk, sig := HelperVerifyData(msg)
	corrupted := make([]byte, len(sig))
	copy(corrupted, sig)
	corrupted[len(corrupted)-1] ^= 0xFF
	assert.False(t, VerifySignature(msg, pk, corrupted))
}

func TestVerifySignature_EmptyInputs(t *testing.T) {
	assert.False(t, VerifySignature(nil, nil, nil))
	assert.False(t, VerifySignature([]byte("msg"), []byte{}, []byte{}))
}

func TestVerifySignature_TruncatedKey(t *testing.T) {
	// Key shorter than 33 bytes
	shortKey := []byte{0x02, 0x01, 0x02}
	dummySig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	assert.False(t, VerifySignature([]byte("test"), shortKey, dummySig))
}
