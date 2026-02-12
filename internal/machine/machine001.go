package machines

import (
	"bytes"
	"github.com/oreparaz/xsig/internal/lowlevel"
	"log"
)

func RunMachine001WithContext(XpPubKey []byte, XpSig []byte, XpMsg []byte, ctx *lowlevel.DeviceContext) bool {
	mc := MachineCode{}
	err := mc.Deserialize(XpSig, CodeTypeXSig)
	if err != nil {
		log.Println("Deserialize", err)
		return false
	}
	e := lowlevel.NewEval()
	e.Context = ctx
	err = e.Eval(mc.Code)
	if err != nil {
		log.Println("Eval part 1", err)
		return false
	}

	intermediateStack := e.Stack.S
	e = lowlevel.NewEval()
	e.Context = ctx
	e.Stack.S = intermediateStack

	err = mc.Deserialize(XpPubKey, CodeTypeXPublicKey)
	if err != nil {
		log.Println("Deserialize:", err)
		return false
	}
	err = e.EvalWithXmsg(mc.Code, XpMsg)
	if err != nil {
		log.Println("Eval part 2", err)
		return false
	}

	expectedEndStack := []byte{byte(1)}
	endStackOk := bytes.Equal(e.Stack.S, expectedEndStack)
	return endStackOk
}

func RunMachine001(XpPubKey []byte, XpSig []byte, XpMsg []byte) bool {
	return RunMachine001WithContext(XpPubKey, XpSig, XpMsg, nil)
}
