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
