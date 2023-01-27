package lowlevel

import (
	"github.com/pkg/errors"
)

func (e *Eval) add() error {
	a, err := e.Stack.Pop()
	if err != nil {
		return errors.Wrapf(err, "add")
	}

	b, err := e.Stack.Pop()
	if err != nil {
		return errors.Wrapf(err, "add")
	}

	e.Stack.Push(a + b)
	return nil
}
