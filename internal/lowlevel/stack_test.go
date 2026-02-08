package lowlevel

import (
	"github.com/oreparaz/xsig/internal/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStack_1(t *testing.T) {
	s := Stack{}

	assert.True(t, s.IsEmpty())

	err := s.Push(1)
	assert.Nil(t, err)

	err = s.Push(42)
	assert.Nil(t, err)

	assert.False(t, s.IsEmpty())

	v1, err := s.Pop()
	assert.Nil(t, err)
	assert.Equal(t, v1, uint8(42))

	v2, err := s.Pop()
	assert.Nil(t, err)
	assert.Equal(t, v2, uint8(1))

	_, err = s.Pop()
	assert.NotNil(t, err)
}

func reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func TestStack_PopPublicKey(t *testing.T) {
	msg := []byte("hello, world")
	_, pk, _ := crypto.HelperVerifyData(msg)

	s := Stack{}
	s.PushBytes([]byte("garbage"))
	s.PushBytes(reverse(pk))
	pkRead, err := s.PopPublicKeyCompressed()
	assert.Nil(t, err)
	assert.Equal(t, pk, reverse(pkRead))
}

func TestStack_PopSignature(t *testing.T) {
	msg := []byte("hello, world")
	_, _, sig := crypto.HelperVerifyData(msg)

	s := Stack{}
	s.PushBytes([]byte("garbage"))
	s.PushBytes(reverse(sig))
	sigRead, err := s.PopSignature()
	assert.Nil(t, err)
	assert.Equal(t, sig, reverse(sigRead))
}

func TestStack_Overflow(t *testing.T) {
	s := Stack{}
	for i := 0; i < MaxStackSize; i++ {
		err := s.Push(1)
		assert.Nil(t, err)
	}
	err := s.Push(1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "stack overflow")
}

func TestStack_PushBytesOverflow(t *testing.T) {
	buf := make([]byte, MaxStackSize+1)
	s := Stack{}
	err := s.PushBytes(buf)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "stack overflow")
}

func TestStack_PopPublicKeyCompressedBadFormat(t *testing.T) {
	s := Stack{}
	// 33 bytes with an invalid format marker (0x05 instead of 0x02/0x03)
	key := make([]byte, 33)
	key[0] = 0x05
	// Push in reverse so that after popping, byte 0 is the format marker
	s.PushBytes(reverse(key))
	_, err := s.PopPublicKeyCompressed()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unknown public key format")
}

func TestStack_PopPublicKeyUncompressedBadFormat(t *testing.T) {
	s := Stack{}
	key := make([]byte, 65)
	key[0] = 0x05 // invalid, should be 0x04
	s.PushBytes(reverse(key))
	_, err := s.PopPublicKeyUncompressed()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unknown public key format")
}

func TestStack_PopPublicKeyCompressedUnderflow(t *testing.T) {
	s := Stack{}
	s.Push(0x02) // only 1 byte, need 33
	_, err := s.PopPublicKeyCompressed()
	assert.NotNil(t, err)
}

func TestStack_PopSignatureInvalidMarker(t *testing.T) {
	s := Stack{}
	s.Push(0x99) // not 0x30
	_, err := s.PopSignature()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "not valid DER encoding")
}

func TestStack_PopSignatureUnderflow(t *testing.T) {
	s := Stack{}
	_, err := s.PopSignature()
	assert.NotNil(t, err)
}

func TestStack_Pop2Underflow(t *testing.T) {
	s := Stack{}
	s.Push(1)
	_, _, err := s.Pop2()
	assert.NotNil(t, err, "Pop2 with only 1 element should fail")
}
