package lowlevel

import (
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
