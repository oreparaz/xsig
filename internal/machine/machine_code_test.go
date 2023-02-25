package machines

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSerialize(t *testing.T) {
	a := MachineCode{}
	xSig := a.Serialize(CodeTypeXSig)

	b := MachineCode{}
	err := b.Deserialize(xSig, CodeTypeXPublicKey)
	assert.Error(t, err)

	c := MachineCode{}
	err = c.Deserialize(xSig, CodeTypeXSig)
	assert.NoError(t, err)
}
