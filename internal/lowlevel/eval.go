package lowlevel

import (
	"github.com/pkg/errors"
)

// DeviceContext provides runtime-supplied device information to the evaluator.
type DeviceContext struct {
	DeviceID []byte // exactly 32 bytes, or nil if not set
}

type Word struct {
	Opcode byte
	Function func() error
}

type Eval struct {
	Stack      Stack
	Dictionary []Word
	Context    *DeviceContext
}

func NewEval() *Eval {
	e := &Eval{}
	e.Dictionary = []Word{
		{OP_ADD, e.add},
		{OP_MUL, e.mul},
		{OP_AND, e.and},
		{OP_OR, e.or},
		{OP_NOT, e.not},
		{OP_EQUAL32, e.equal32},
	}
	return e
}

// references:
// bitcoin core interpreter:  https://github.com/bitcoin/bitcoin/blob/48efbdbe986355bd2478f0fdd366b20952fbf30a/src/script/interpreter.cpp
// compact Forth interpreter: https://github.com/skx/foth/blob/master/part1/eval.go

func (e *Eval) EvalWithXmsg(code []byte, xmsg []byte) error {
	pc := 0
	pend := len(code)

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
			if pc+1 >= pend {
				return errors.New("OP_PUSH: missing length operand")
			}
			howMany := int(code[pc+1])
			if pc+2+howMany > pend {
				return errors.Errorf("OP_PUSH: operand extends past end of code (%d bytes needed, %d available)", howMany, pend-pc-2)
			}
			for i:=0; i < howMany; i++ {
				err := e.Stack.Push(code[pc+2+i])
				if err != nil {
					return errors.Wrapf(err, "overflow")
				}
			}
			pc = pc + 2 + howMany
			goto end
		case OP_SIGVERIFY:
			err := e.sigverify(xmsg)
			if err != nil {
				return err
			}
			goto next
		case OP_MULTISIGVERIFY:
			err := e.multisigverify(xmsg)
			if err != nil {
				return err
			}
			goto next
		case OP_DEVICEID:
			if e.Context == nil || len(e.Context.DeviceID) != 32 {
				return errors.New("OP_DEVICEID: no device context set")
			}
			for i := 31; i >= 0; i-- {
				err := e.Stack.Push(e.Context.DeviceID[i])
				if err != nil {
					return errors.Wrapf(err, "OP_DEVICEID")
				}
			}
			goto next
		default:
			return errors.Errorf("unknown opcode %v", opcode)
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
