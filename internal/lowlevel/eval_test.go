package lowlevel

import (
	"github.com/oreparaz/xsig/internal/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEval_Eval(t *testing.T) {
	code := []byte{OP_PUSH, byte(1), byte(1), OP_PUSH, byte(1), byte(42), OP_ADD}
	e := NewEval()
	err := e.Eval(code)
	assert.Nil(t, err)

	expectedStack := []byte{byte(43)}
	assert.Equal(t, e.Stack.S, expectedStack)
}

func TestEval_Eval2(t *testing.T) {
	code := []byte{OP_PUSH, byte(1), byte(1), OP_PUSH, byte(1), byte(42), OP_ADD, OP_PUSH, byte(1), byte(3), OP_MUL}
	e := NewEval()
	err := e.Eval(code)
	assert.Nil(t, err)

	expectedStack := []byte{byte(129)}
	assert.Equal(t, e.Stack.S, expectedStack)
}

func TestEval_And(t *testing.T) {
	code := []byte{OP_PUSH, byte(1), byte(0x0F), OP_PUSH, byte(1), byte(0x55), OP_AND}
	e := NewEval()
	err := e.Eval(code)
	assert.Nil(t, err)

	expectedStack := []byte{byte(0x05)}
	assert.Equal(t, e.Stack.S, expectedStack)
}

func TestEval_Or(t *testing.T) {
	code := []byte{OP_PUSH, byte(1), byte(0x0F), OP_PUSH, byte(1), byte(0x55), OP_OR}
	e := NewEval()
	err := e.Eval(code)
	assert.Nil(t, err)

	expectedStack := []byte{byte(0x5F)}
	assert.Equal(t, e.Stack.S, expectedStack)
}

func TestEval_Not(t *testing.T) {
	code := []byte{OP_PUSH, byte(1), byte(0x55), OP_NOT}
	e := NewEval()
	err := e.Eval(code)
	assert.Nil(t, err)

	expectedStack := []byte{byte(0xAA)}
	assert.Equal(t, e.Stack.S, expectedStack)
}

func TestEval_MultisigverifyEmptyStackShouldFail(t *testing.T) {
	code := []byte{OP_MULTISIGVERIFY}
	e := NewEval()
	err := e.EvalWithXmsg(code, []byte("msg"))
	assert.NotNil(t, err, "multisigverify on empty stack should error, not silently succeed")
}

func TestEval_PushTruncatedLength(t *testing.T) {
	code := []byte{OP_PUSH}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err, "OP_PUSH without length byte should fail")
}

func TestEval_PushTruncatedOperand(t *testing.T) {
	code := []byte{OP_PUSH, byte(5), byte(1), byte(2)}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err, "OP_PUSH with fewer bytes than length should fail")
}

func TestEval_MultisigverifyZeroPublicKeys(t *testing.T) {
	// push nMinValid=1 then nPublicKeys=0
	code := []byte{OP_PUSH, 1, 1, OP_PUSH, 1, 0, OP_MULTISIGVERIFY}
	e := NewEval()
	err := e.EvalWithXmsg(code, []byte("msg"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "nPublicKeys must be > 0")
}

func TestEval_MultisigverifyZeroMinValid(t *testing.T) {
	// push nMinValid=0 then nPublicKeys=2
	code := []byte{OP_PUSH, 1, 0, OP_PUSH, 1, 2, OP_MULTISIGVERIFY}
	e := NewEval()
	err := e.EvalWithXmsg(code, []byte("msg"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "nMinValid must be > 0")
}

func TestEval_MultisigverifyMinValidGreaterThanPublicKeys(t *testing.T) {
	// push nMinValid=5 then nPublicKeys=2
	code := []byte{OP_PUSH, 1, 5, OP_PUSH, 1, 2, OP_MULTISIGVERIFY}
	e := NewEval()
	err := e.EvalWithXmsg(code, []byte("msg"))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "nMinValid (5) > nPublicKeys (2)")
}

func TestEval_Push(t *testing.T) {
	a := Assembler{}
	a.Append(Push([]byte{byte(4), byte(5)}))
	a.Append(Push1(6))
	e := NewEval()
	err := e.Eval(a.Code)
	assert.Nil(t, err)
	expectedStack := []byte{byte(5), byte(4), byte(6)}
	assert.Equal(t, e.Stack.S, expectedStack)
}

func TestEval_PushZeroLength(t *testing.T) {
	code := []byte{OP_PUSH, 0}
	e := NewEval()
	err := e.Eval(code)
	assert.Nil(t, err)
	assert.True(t, e.Stack.IsEmpty())
}

func TestEval_EmptyProgram(t *testing.T) {
	e := NewEval()
	err := e.Eval([]byte{})
	assert.Nil(t, err)
	assert.True(t, e.Stack.IsEmpty())
}

func TestEval_UnknownOpcode(t *testing.T) {
	code := []byte{0xFF}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unknown opcode")
}

func TestEval_SigverifyWrongMessage(t *testing.T) {
	msg := []byte("hello")
	_, pk, sig := crypto.HelperVerifyData(msg)

	a := Assembler{}
	a.Append(Push(sig))
	a.Append(Push(pk))
	a.Append(SignatureVerify())

	e := NewEval()
	err := e.EvalWithXmsg(a.Code, []byte("wrong message"))
	assert.Nil(t, err, "sigverify with wrong message should not error, just push 0")
	assert.Equal(t, []byte{0}, e.Stack.S, "sigverify with wrong message should push 0")
}

func TestEval_SigverifyCorrectMessage(t *testing.T) {
	msg := []byte("hello")
	_, pk, sig := crypto.HelperVerifyData(msg)

	a := Assembler{}
	a.Append(Push(sig))
	a.Append(Push(pk))
	a.Append(SignatureVerify())

	e := NewEval()
	err := e.EvalWithXmsg(a.Code, msg)
	assert.Nil(t, err)
	assert.Equal(t, []byte{1}, e.Stack.S, "sigverify with correct message should push 1")
}

func TestEval_SigverifyEmptyStackShouldFail(t *testing.T) {
	code := []byte{OP_SIGVERIFY}
	e := NewEval()
	err := e.EvalWithXmsg(code, []byte("msg"))
	assert.NotNil(t, err, "sigverify on empty stack should error")
}

func TestEval_SigverifyPopSignatureError(t *testing.T) {
	// Push a valid compressed key but no signature — PopSignature should fail
	msg := []byte("hello")
	_, pk, _ := crypto.HelperVerifyData(msg)

	a := Assembler{}
	a.Append(Push(pk))
	a.Append(SignatureVerify())

	e := NewEval()
	err := e.EvalWithXmsg(a.Code, msg)
	assert.NotNil(t, err, "sigverify with key but no signature should error")
}

func TestEval_AddEmptyStack(t *testing.T) {
	code := []byte{OP_ADD}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err, "add on empty stack should error")
}

func TestEval_MulEmptyStack(t *testing.T) {
	code := []byte{OP_MUL}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err)
}

func TestEval_AndEmptyStack(t *testing.T) {
	code := []byte{OP_AND}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err)
}

func TestEval_OrEmptyStack(t *testing.T) {
	code := []byte{OP_OR}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err)
}

func TestEval_NotEmptyStack(t *testing.T) {
	code := []byte{OP_NOT}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err)
}

func TestEval_MultisigverifyFullFlow(t *testing.T) {
	// Full end-to-end multisigverify at the lowlevel package level
	msg := []byte("test")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, sig2 := crypto.HelperVerifyData(msg)
	_, pk3, _ := crypto.HelperVerifyData(msg)

	// Build program: push sigs, push keys, push params, multisigverify
	a := Assembler{}
	a.Append(Push(sig1))
	a.Append(Push(sig2))
	a.Append(Push(pk1))
	a.Append(Push(pk2))
	a.Append(Push(pk3))
	a.Append(Push1(2))  // nMinValid
	a.Append(Push1(3))  // nPublicKeys
	a.Append(MultisigVerify())

	e := NewEval()
	err := e.EvalWithXmsg(a.Code, msg)
	assert.Nil(t, err)
	assert.Equal(t, []byte{1}, e.Stack.S, "2-of-3 multisig with valid sigs should push 1")
}

func TestEval_MultisigverifyFullFlowFail(t *testing.T) {
	// multisigverify with wrong message should push 0
	msg := []byte("test")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, sig2 := crypto.HelperVerifyData(msg)
	_, pk3, _ := crypto.HelperVerifyData(msg)

	a := Assembler{}
	a.Append(Push(sig1))
	a.Append(Push(sig2))
	a.Append(Push(pk1))
	a.Append(Push(pk2))
	a.Append(Push(pk3))
	a.Append(Push1(2))
	a.Append(Push1(3))
	a.Append(MultisigVerify())

	e := NewEval()
	err := e.EvalWithXmsg(a.Code, []byte("wrong"))
	assert.Nil(t, err)
	assert.Equal(t, []byte{0}, e.Stack.S, "multisig with wrong message should push 0")
}

func TestEval_MultisigverifyPopKeyError(t *testing.T) {
	// Valid params but not enough data on stack for keys
	code := []byte{OP_PUSH, 1, 1, OP_PUSH, 1, 1, OP_MULTISIGVERIFY}
	e := NewEval()
	err := e.EvalWithXmsg(code, []byte("msg"))
	assert.NotNil(t, err, "multisigverify with missing key data should error")
}

func TestEval_MultisigverifyPopSigError(t *testing.T) {
	// Push 1 valid key but no signature data — keys pop fine, sig pop fails
	msg := []byte("test")
	_, pk1, _ := crypto.HelperVerifyData(msg)

	a := Assembler{}
	// no signatures pushed
	a.Append(Push(pk1))
	a.Append(Push1(1)) // nMinValid
	a.Append(Push1(1)) // nPublicKeys
	a.Append(MultisigVerify())

	e := NewEval()
	err := e.EvalWithXmsg(a.Code, msg)
	assert.NotNil(t, err, "multisigverify should fail when signature data is missing")
}

func TestEval_PushStackOverflow(t *testing.T) {
	// Fill stack close to capacity, then have OP_PUSH overflow it
	e := NewEval()
	for i := 0; i < MaxStackSize-1; i++ {
		e.Stack.Push(0)
	}
	// Now push 2 bytes — first succeeds, second overflows
	code := []byte{OP_PUSH, 2, 0xAA, 0xBB}
	err := e.Eval(code)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "overflow")
}

func TestAssembler_PushLengthOverflow(t *testing.T) {
	data := make([]byte, 256)
	a := Assembler{}
	err := a.Append(Push(data))
	assert.NotNil(t, err, "assembler should reject Push with > 255 bytes")
	assert.Contains(t, err.Error(), "too large")
}

func TestAssembler_PushMaxLength(t *testing.T) {
	data := make([]byte, 255)
	a := Assembler{}
	err := a.Append(Push(data))
	assert.Nil(t, err, "assembler should accept Push with exactly 255 bytes")
}

func TestEval_Equal32_Match(t *testing.T) {
	data := make([]byte, 32)
	for i := range data { data[i] = byte(i) }
	a := Assembler{}
	a.Append(Push(data))
	a.Append(Push(data))
	a.Append(Equal32())
	e := NewEval()
	err := e.Eval(a.Code)
	assert.Nil(t, err)
	assert.Equal(t, []byte{1}, e.Stack.S)
}

func TestEval_Equal32_Mismatch(t *testing.T) {
	d1 := make([]byte, 32)
	d2 := make([]byte, 32)
	d2[0] = 0xFF
	a := Assembler{}
	a.Append(Push(d1))
	a.Append(Push(d2))
	a.Append(Equal32())
	e := NewEval()
	err := e.Eval(a.Code)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0}, e.Stack.S)
}

func TestEval_Equal32_EmptyStack(t *testing.T) {
	code := []byte{OP_EQUAL32}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err)
}

func TestEval_Equal32_Underflow(t *testing.T) {
	// Push only 31 bytes + 32 bytes = 63 bytes, need 64
	a := Assembler{}
	a.Append(Push(make([]byte, 31)))
	a.Append(Push(make([]byte, 32)))
	a.Append(Equal32())
	e := NewEval()
	err := e.Eval(a.Code)
	assert.NotNil(t, err)
}

func TestEval_DeviceID_WithContext(t *testing.T) {
	deviceID := make([]byte, 32)
	for i := range deviceID { deviceID[i] = byte(i + 0x10) }
	e := NewEval()
	e.Context = &DeviceContext{DeviceID: deviceID}
	a := Assembler{}
	a.Append(DeviceID())
	err := e.Eval(a.Code)
	assert.Nil(t, err)
	assert.Equal(t, 32, len(e.Stack.S))
}

func TestEval_DeviceID_NoContext(t *testing.T) {
	code := []byte{OP_DEVICEID}
	e := NewEval()
	err := e.Eval(code)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "OP_DEVICEID")
}

func TestEval_DeviceID_Equal32_Match(t *testing.T) {
	deviceID := make([]byte, 32)
	for i := range deviceID { deviceID[i] = byte(i + 0xA0) }
	e := NewEval()
	e.Context = &DeviceContext{DeviceID: deviceID}
	a := Assembler{}
	a.Append(Push(deviceID))
	a.Append(DeviceID())
	a.Append(Equal32())
	err := e.Eval(a.Code)
	assert.Nil(t, err)
	assert.Equal(t, []byte{1}, e.Stack.S)
}

func TestEval_DeviceID_Equal32_Mismatch(t *testing.T) {
	deviceID := make([]byte, 32)
	for i := range deviceID { deviceID[i] = byte(i + 0xA0) }
	wrongID := make([]byte, 32)
	e := NewEval()
	e.Context = &DeviceContext{DeviceID: deviceID}
	a := Assembler{}
	a.Append(Push(wrongID))
	a.Append(DeviceID())
	a.Append(Equal32())
	err := e.Eval(a.Code)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0}, e.Stack.S)
}
