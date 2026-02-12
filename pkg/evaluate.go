package pkg

import (
	machines "github.com/oreparaz/xsig/internal/machine"
	"github.com/oreparaz/xsig/internal/lowlevel"
)

func EvaluateXSig(XpPubKey []byte, XpSig []byte, XpMsg []byte) bool {
	return machines.RunMachine001(XpPubKey, XpSig, XpMsg)
}

func EvaluateXSigWithContext(XpPubKey []byte, XpSig []byte, XpMsg []byte, ctx *lowlevel.DeviceContext) bool {
	return machines.RunMachine001WithContext(XpPubKey, XpSig, XpMsg, ctx)
}
