package machines

import (
	"bytes"
	"github.com/oreparaz/xsig/internal/lowlevel"
	"log"
)

func RunMachine001(XpPubKey []byte, XpSig []byte, XpMsg []byte) bool {
	// TODO: bind opcodes to machine variant
	// TODO: introduce a marker for a XpPubKey script and XpSig script
	e := lowlevel.NewEval()
	err := e.Eval(XpSig)
	if err != nil {
		log.Println("Eval part 1", err)
		return false
	}

	intermediateStack := e.Stack.S
	e = lowlevel.NewEval()
	e.Stack.S = intermediateStack

	err = e.EvalWithXmsg(XpPubKey, XpMsg)
	if err != nil {
		log.Println("Eval part 2", err)
		return false
	}

	expectedEndStack := []byte{byte(1)}
	endStackOk := bytes.Equal(e.Stack.S, expectedEndStack)
	return endStackOk
}
