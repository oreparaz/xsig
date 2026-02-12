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

func TestRunMachine001_WrongMessage(t *testing.T) {
	msg := []byte("correct")
	_, pk, sig := crypto.HelperVerifyData(msg)

	a := MachineCode{}
	a.Append(ll.Push(sig))
	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push(pk))
	b.Append(ll.SignatureVerify())
	xPubKey := b.Serialize(CodeTypeXPublicKey)

	assert.False(t, RunMachine001(xPubKey, xSig, []byte("wrong")),
		"signature verified against wrong message should fail")
}

func TestRunMachine001_1of1Multisig(t *testing.T) {
	msg := []byte("test")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)

	a := MachineCode{}
	a.Append(ll.Push(sig1))
	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push(pk1))
	b.Append(ll.Push1(1))
	b.Append(ll.Push1(1))
	b.Append(ll.MultisigVerify())
	xPubKey := b.Serialize(CodeTypeXPublicKey)

	assert.True(t, RunMachine001(xPubKey, xSig, msg))
}

func TestRunMachine001_3of3Multisig(t *testing.T) {
	msg := []byte("test")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, sig2 := crypto.HelperVerifyData(msg)
	_, pk3, sig3 := crypto.HelperVerifyData(msg)

	a := MachineCode{}
	a.Append(ll.Push(sig1))
	a.Append(ll.Push(sig2))
	a.Append(ll.Push(sig3))
	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push(pk1))
	b.Append(ll.Push(pk2))
	b.Append(ll.Push(pk3))
	b.Append(ll.Push1(3))
	b.Append(ll.Push1(3))
	b.Append(ll.MultisigVerify())
	xPubKey := b.Serialize(CodeTypeXPublicKey)

	assert.True(t, RunMachine001(xPubKey, xSig, msg),
		"3-of-3 multisig with all valid signatures should pass")
}

func TestRunMachine001_3of3MultisigMissingSig(t *testing.T) {
	msg := []byte("test")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, sig2 := crypto.HelperVerifyData(msg)
	_, pk3, _ := crypto.HelperVerifyData(msg)

	// only provide 2 of 3 required sigs (repeat sig1 for the third)
	a := MachineCode{}
	a.Append(ll.Push(sig1))
	a.Append(ll.Push(sig2))
	a.Append(ll.Push(sig1))
	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push(pk1))
	b.Append(ll.Push(pk2))
	b.Append(ll.Push(pk3))
	b.Append(ll.Push1(3))
	b.Append(ll.Push1(3))
	b.Append(ll.MultisigVerify())
	xPubKey := b.Serialize(CodeTypeXPublicKey)

	assert.False(t, RunMachine001(xPubKey, xSig, msg),
		"3-of-3 with only 2 distinct valid signers should fail")
}

func TestRunMachine001_DuplicateSigsDistinctKeys(t *testing.T) {
	// Same signature provided twice with distinct keys — should NOT satisfy 2-of-3
	msg := []byte("test")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, _ := crypto.HelperVerifyData(msg)
	_, pk3, _ := crypto.HelperVerifyData(msg)

	a := MachineCode{}
	a.Append(ll.Push(sig1))
	a.Append(ll.Push(sig1)) // duplicate signature
	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push(pk1))
	b.Append(ll.Push(pk2))
	b.Append(ll.Push(pk3))
	b.Append(ll.Push1(2))
	b.Append(ll.Push1(3))
	b.Append(ll.MultisigVerify())
	xPubKey := b.Serialize(CodeTypeXPublicKey)

	assert.False(t, RunMachine001(xPubKey, xSig, msg),
		"duplicate signatures from same signer should not satisfy quorum")
}

func TestRunMachine001_MultisigWrongMessage(t *testing.T) {
	msg := []byte("correct")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, sig2 := crypto.HelperVerifyData(msg)
	_, pk3, _ := crypto.HelperVerifyData(msg)

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

	assert.False(t, RunMachine001(xPubKey, xSig, []byte("wrong")),
		"multisig against wrong message should fail")
}

func TestRunMachine001_EmptyXSig(t *testing.T) {
	assert.False(t, RunMachine001([]byte{}, []byte{}, []byte("msg")))
}

func TestRunMachine001_GarbagePrefix(t *testing.T) {
	assert.False(t, RunMachine001([]byte("garbage"), []byte("garbage"), []byte("msg")))
}

func TestRunMachine001_XSigEvalError(t *testing.T) {
	// Valid xsig prefix but contains an unknown opcode → eval part 1 fails
	mc := MachineCode{}
	mc.Code = []byte{0xFF} // unknown opcode
	xSig := mc.Serialize(CodeTypeXSig)

	b := MachineCode{}
	b.Append(ll.Push1(1))
	xPubKey := b.Serialize(CodeTypeXPublicKey)

	assert.False(t, RunMachine001(xPubKey, xSig, []byte("msg")))
}

func TestRunMachine001_XPubKeyBadPrefix(t *testing.T) {
	// Valid xsig, but xpubkey has wrong prefix
	a := MachineCode{}
	a.Append(ll.Push1(1))
	xSig := a.Serialize(CodeTypeXSig)

	assert.False(t, RunMachine001([]byte("garbage"), xSig, []byte("msg")))
}

func TestRunMachine001_XPubKeyEvalError(t *testing.T) {
	// Valid xsig (eval succeeds), valid xpubkey prefix but code has unknown opcode
	a := MachineCode{}
	a.Append(ll.Push1(1))
	xSig := a.Serialize(CodeTypeXSig)

	mc := MachineCode{}
	mc.Code = []byte{0xFF}
	xPubKey := mc.Serialize(CodeTypeXPublicKey)

	assert.False(t, RunMachine001(xPubKey, xSig, []byte("msg")))
}

func TestRunMachine001_DeviceID_Match(t *testing.T) {
	deviceID := make([]byte, 32)
	for i := range deviceID { deviceID[i] = byte(i + 0x42) }
	ctx := &ll.DeviceContext{DeviceID: deviceID}

	// xsig: empty (no data needed)
	xSig := MachineCode{}
	xSigSer := xSig.Serialize(CodeTypeXSig)

	// xpubkey: PUSH(expected_serial) DEVICEID EQUAL32
	xPK := MachineCode{}
	xPK.Append(ll.Push(deviceID))
	xPK.Append(ll.DeviceID())
	xPK.Append(ll.Equal32())
	xPKSer := xPK.Serialize(CodeTypeXPublicKey)

	assert.True(t, RunMachine001WithContext(xPKSer, xSigSer, []byte("msg"), ctx))
}

func TestRunMachine001_DeviceID_Mismatch(t *testing.T) {
	deviceID := make([]byte, 32)
	for i := range deviceID { deviceID[i] = byte(i + 0x42) }
	ctx := &ll.DeviceContext{DeviceID: deviceID}

	wrongID := make([]byte, 32)

	xSig := MachineCode{}
	xSigSer := xSig.Serialize(CodeTypeXSig)

	xPK := MachineCode{}
	xPK.Append(ll.Push(wrongID))
	xPK.Append(ll.DeviceID())
	xPK.Append(ll.Equal32())
	xPKSer := xPK.Serialize(CodeTypeXPublicKey)

	assert.False(t, RunMachine001WithContext(xPKSer, xSigSer, []byte("msg"), ctx))
}

func TestRunMachine001_DeviceID_NoContext(t *testing.T) {
	deviceID := make([]byte, 32)

	xSig := MachineCode{}
	xSigSer := xSig.Serialize(CodeTypeXSig)

	xPK := MachineCode{}
	xPK.Append(ll.Push(deviceID))
	xPK.Append(ll.DeviceID())
	xPK.Append(ll.Equal32())
	xPKSer := xPK.Serialize(CodeTypeXPublicKey)

	// No context → OP_DEVICEID should fail → machine returns false
	assert.False(t, RunMachine001(xPKSer, xSigSer, []byte("msg")))
}

func TestRunMachine001_DeviceID_WithSigverify(t *testing.T) {
	// Combined test: require both valid signature AND correct device ID
	msg := []byte("firmware-v1.2")
	_, pk, sig := crypto.HelperVerifyData(msg)

	deviceID := make([]byte, 32)
	for i := range deviceID { deviceID[i] = byte(i + 0x10) }
	ctx := &ll.DeviceContext{DeviceID: deviceID}

	// xsig: push signature
	xSigMC := MachineCode{}
	xSigMC.Append(ll.Push(sig))
	xSigSer := xSigMC.Serialize(CodeTypeXSig)

	// xpubkey: PUSH(pk) SIGVERIFY PUSH(expected_serial) DEVICEID EQUAL32 AND
	xPK := MachineCode{}
	xPK.Append(ll.Push(pk))
	xPK.Append(ll.SignatureVerify())
	xPK.Append(ll.Push(deviceID))
	xPK.Append(ll.DeviceID())
	xPK.Append(ll.Equal32())
	xPK.Append(ll.And())
	xPKSer := xPK.Serialize(CodeTypeXPublicKey)

	assert.True(t, RunMachine001WithContext(xPKSer, xSigSer, msg, ctx))

	// Wrong device → should fail
	wrongCtx := &ll.DeviceContext{DeviceID: make([]byte, 32)}
	assert.False(t, RunMachine001WithContext(xPKSer, xSigSer, msg, wrongCtx))
}
