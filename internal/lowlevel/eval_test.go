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
