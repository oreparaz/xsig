package lowlevel

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAssembler_Small(t *testing.T) {
	a := Assembler{}
	a.Append(Push1(1))
	a.Append(Push1(42))
	a.Append(Add())

	code := []byte{OP_PUSH, byte(1), byte(1), OP_PUSH, byte(1), byte(42), OP_ADD}

	assert.Equal(t, a.Code, code)
}

func TestAssembler_Small2(t *testing.T) {
	a := Assembler{}
	a.Append(Push1(1))
	a.Append(Push1(42))
	a.Append(Add())
	a.Append(Push1(3))
	a.Append(Mul())

	code := []byte{OP_PUSH, byte(1), byte(1), OP_PUSH, byte(1), byte(42), OP_ADD, OP_PUSH, byte(1), byte(3), OP_MUL}

	assert.Equal(t, a.Code, code)
}

func TestAssembler_AllConstructors(t *testing.T) {
	// Exercise And, Or, Not, MultisigVerify, SignatureVerify constructors
	assert.Equal(t, OP_AND, And().Opcode)
	assert.Equal(t, OP_OR, Or().Opcode)
	assert.Equal(t, OP_NOT, Not().Opcode)
	assert.Equal(t, OP_MULTISIGVERIFY, MultisigVerify().Opcode)
	assert.Equal(t, OP_SIGVERIFY, SignatureVerify().Opcode)
	assert.Equal(t, OP_EQUAL32, Equal32().Opcode)
	assert.Equal(t, OP_DEVICEID, DeviceID().Opcode)

	// Verify they produce correct bytecode through Append
	a := Assembler{}
	a.Append(And())
	a.Append(Or())
	a.Append(Not())
	a.Append(MultisigVerify())
	expected := []byte{OP_AND, OP_OR, OP_NOT, OP_MULTISIGVERIFY}
	assert.Equal(t, expected, a.Code)
}

func TestAssembler_AppendNonPushReturnsNil(t *testing.T) {
	a := Assembler{}
	assert.Nil(t, a.Append(Add()))
	assert.Nil(t, a.Append(And()))
	assert.Nil(t, a.Append(SignatureVerify()))
}
