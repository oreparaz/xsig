package lowlevel

import (
	"github.com/pkg/errors"
)

type Word struct {
	Opcode byte
	Function func() error
}

type Eval struct {
	Stack      Stack
	Dictionary []Word
}

func NewEval() *Eval {
	e := &Eval{}
	e.Dictionary = []Word{
		{OP_ADD, e.add},
	}
	return e
}

// references:
// bitcoin core interpreter:  https://github.com/bitcoin/bitcoin/blob/48efbdbe986355bd2478f0fdd366b20952fbf30a/src/script/interpreter.cpp
// compact Forth interpreter: https://github.com/skx/foth/blob/master/part1/eval.go

func (e *Eval) EvalWithXmsg(code []byte, xmsg []byte) error {
	pc := 0
	pend := len(code)

	// TODO guard all accesses to code[pc], code[pc+1], etc etc
	for pc < pend {
		opcode := code[pc]

		for _, word := range e.Dictionary {
			if opcode == word.Opcode {
				err := word.Function()
				if err != nil {
					return err
				}
				goto next
			}
		}

		switch opcode {
		case OP_PUSH:
			howMany := int(code[pc+1])
			for i:=0; i < howMany; i++ {
				err := e.Stack.Push(code[pc+2+i])
				if err != nil {
					return errors.Wrapf(err, "overflow")
				}
			}
			pc = pc + 2 + howMany
			goto end
		}

	next:
		pc = pc + 1
	end:
	}
	return nil
}

func (e *Eval) Eval(code []byte) error {
	return e.EvalWithXmsg(code, []byte{})
}
