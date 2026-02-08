package pkg

import (
	"github.com/oreparaz/xsig/internal/crypto"
	ll "github.com/oreparaz/xsig/internal/lowlevel"
	machines "github.com/oreparaz/xsig/internal/machine"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEvaluateXSig(t *testing.T) {
	msg := []byte("hello")
	_, pk, sig := crypto.HelperVerifyData(msg)

	a := machines.MachineCode{}
	a.Append(ll.Push(sig))
	xSig := a.Serialize(machines.CodeTypeXSig)

	b := machines.MachineCode{}
	b.Append(ll.Push(pk))
	b.Append(ll.SignatureVerify())
	xPubKey := b.Serialize(machines.CodeTypeXPublicKey)

	assert.True(t, EvaluateXSig(xPubKey, xSig, msg))
	assert.False(t, EvaluateXSig(xPubKey, xSig, []byte("wrong")))
}

func TestEvaluateXSig_Invalid(t *testing.T) {
	assert.False(t, EvaluateXSig(nil, nil, nil))
}
