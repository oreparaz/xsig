package lowlevel

import (
	"github.com/oreparaz/xsig/internal/crypto"
	"github.com/pkg/errors"
)

func (e *Eval) add() error {
	a, b, err := e.Stack.Pop2() // first we pop a and then b
	if err != nil {
		return errors.Wrapf(err, "add")
	}
	e.Stack.Push(a + b)
	return nil
}

func (e *Eval) mul() error {
	a, b, err := e.Stack.Pop2()
	if err != nil {
		return errors.Wrapf(err, "mul")
	}
	e.Stack.Push(a * b)
	return nil
}

func (e *Eval) and() error {
	a, b, err := e.Stack.Pop2()
	if err != nil {
		return errors.Wrapf(err, "and")
	}
	e.Stack.Push(a & b)
	return nil
}

func (e *Eval) or() error {
	a, b, err := e.Stack.Pop2()
	if err != nil {
		return errors.Wrapf(err, "or")
	}
	e.Stack.Push(a | b)
	return nil
}

func (e *Eval) not() error {
	a, err := e.Stack.Pop()
	if err != nil {
		return errors.Wrapf(err, "not")
	}
	e.Stack.Push(^a)
	return nil
}

func (e *Eval) sigverify(xmsg []byte) error {
	publicKey, err := e.Stack.PopPublicKey()
	if err != nil {
		return errors.Wrapf(err, "PopPublicKey")
	}

	sig, err := e.Stack.PopSignature()
	if err != nil {
		return errors.Wrapf(err, "PopSignature")
	}

	signatureValidates := crypto.VerifySignature(xmsg, publicKey, sig)

	if signatureValidates {
		e.Stack.Push(1)
	} else {
		e.Stack.Push(0)
	}
	return nil
}
