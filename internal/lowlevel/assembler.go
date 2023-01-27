package lowlevel

type Assembler struct {
	Code []byte
}

type Instruction struct {
	Opcode byte
	Literal []byte
}

func Add() Instruction {
	return Instruction{ Opcode: OP_ADD }
}

func Mul() Instruction {
	return Instruction{ Opcode: OP_MUL }
}

func And() Instruction {
	return Instruction{ Opcode: OP_AND }
}

func Or() Instruction {
	return Instruction{ Opcode: OP_OR }
}

func Not() Instruction {
	return Instruction{ Opcode: OP_NOT }
}

func Push1(literal int) Instruction {
	return Instruction{
		Opcode: OP_PUSH,
		Literal: []byte{byte(literal)},
	}
}

func Push(data []byte) Instruction {
	return Instruction{
		Opcode: OP_PUSH,
		Literal: data,
	}
}

func SignatureVerify() Instruction {
	return Instruction{ Opcode: OP_SIGVERIFY }
}

func (a *Assembler) Append(in Instruction) {
	a.Code = append(a.Code, in.Opcode)
	if in.Opcode == OP_PUSH {
		// TODO check this number is sane
		ll := len(in.Literal)
		a.Code = append(a.Code, byte(ll))

		for i:=0; i<ll; i++ {
			a.Code = append(a.Code, in.Literal[ll-i-1])
		}
	}
}
