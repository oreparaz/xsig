package pkg

import machines "github.com/oreparaz/xsig/internal/machine"

func EvaluateXSig(XpPubKey []byte, XpSig []byte, XpMsg []byte) bool {
	return machines.RunMachine001(XpPubKey, XpSig, XpMsg)
}
