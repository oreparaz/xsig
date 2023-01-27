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
