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

	a := MachineCode{}
	a.Append(ll.Push(sig))

	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push(publicKeyBytes))
	b.Append(ll.SignatureVerify())

	xPubKey := b.Serialize(CodeTypeXPublicKey)

	assert.True(t, RunMachine001(xPubKey, xSig, msg))
}

func helperTestMultisignature(msg, pk1, pk2, pk3, sig1, sig2 []byte) bool {
	a := MachineCode{}
	a.Append(ll.Push(sig1))
	a.Append(ll.Push(sig2))

	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push(pk1))
	b.Append(ll.Push(pk2))
	b.Append(ll.Push(pk3))
	b.Append(ll.Push1(2))
	b.Append(ll.Push1(3))

	b.Append(ll.MultisigVerify())

	xPubKey := b.Serialize(CodeTypeXPublicKey)

	return RunMachine001(xPubKey, xSig, msg)
}

func TestRunMachine2023012_Multisig(t *testing.T) {
	msg := []byte("yolo")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, sig2 := crypto.HelperVerifyData(msg)
	_, pk3, sig3 := crypto.HelperVerifyData(msg)

	assert.True(t, helperTestMultisignature(msg, pk1, pk2, pk3, sig1, sig2))
	assert.True(t, helperTestMultisignature(msg, pk1, pk2, pk3, sig2, sig1))
	assert.True(t, helperTestMultisignature(msg, pk1, pk2, pk3, sig3, sig2))
	assert.True(t, helperTestMultisignature(msg, pk1, pk2, pk3, sig3, sig1))

	// mind this case: repeated public keys are accepted and count towards quorum
	assert.True(t, helperTestMultisignature(msg, pk1, pk1, pk3, sig1, sig2))

	assert.False(t, helperTestMultisignature(msg, pk1, pk2, pk3, sig1, sig1))
	assert.False(t, helperTestMultisignature(msg, pk1, pk2, pk3, sig2, sig2))

	assert.False(t, helperTestMultisignature(msg, pk1, pk1, pk3, sig2, sig3))
	assert.False(t, helperTestMultisignature(msg, pk1, pk3, pk3, sig1, sig2))
}
