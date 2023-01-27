package machines

import (
	"github.com/oreparaz/xsig/internal/crypto"
	ll "github.com/oreparaz/xsig/internal/lowlevel"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRunMachine001(t *testing.T) {
	msg := []byte("yolo")
	_, publicKeyBytes, sig := crypto.HelperVerifyData(msg)

	a := ll.Assembler{}
	a.Append(ll.Push(sig))

	xSig := a.Code

	b := ll.Assembler{}
	b.Append(ll.Push(publicKeyBytes))
	b.Append(ll.SignatureVerify())

	xPubKey := b.Code

	assert.True(t, RunMachine001(xPubKey, xSig, msg))
}
