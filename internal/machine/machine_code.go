package machines

import (
	"bytes"
	"github.com/oreparaz/xsig/internal/lowlevel"
	"github.com/pkg/errors"
)

type MachineCode struct {
	lowlevel.Assembler
}

type MachineType uint8
type CodeType uint8

const (
	GlobalMagic string = "xsig"
)

const (
	MachineTypeMachine001 MachineType = 0
)

const (
	CodeTypeXPublicKey CodeType = 0
	CodeTypeXSig CodeType = 1
)

func prefix(codeType CodeType) []byte {
	x := []byte(GlobalMagic)
	x = append(x, byte(MachineTypeMachine001))
	x = append(x, byte(codeType))
	return x
}

func (m *MachineCode) Serialize(codeType CodeType) []byte {
	return append(prefix(codeType), m.Code...)
}

func (m *MachineCode) Deserialize(x []byte, expectedCodeType CodeType) error {
	expectedPrefix := prefix(expectedCodeType)
	if !bytes.HasPrefix(x, expectedPrefix) {
		return errors.New("wrong prefix")
	}
	m.Code = bytes.TrimPrefix(x, expectedPrefix)
	return nil
}
