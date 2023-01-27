package lowlevel

import (
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
