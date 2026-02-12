// +build ignore

// Generates comprehensive test vectors for the C xsig implementation.
// Run from project root: go run ./c/gen_test_vectors.go
package main

import (
	"fmt"
	"math/rand"
	"os"

	"github.com/oreparaz/xsig/internal/crypto"
	ll "github.com/oreparaz/xsig/internal/lowlevel"
	machines "github.com/oreparaz/xsig/internal/machine"
)

// ---- types ----

type EvalTV struct {
	Name        string
	Code        []byte
	Msg         []byte
	DeviceID    []byte
	ExpectError bool
	ExpectStack []byte
}

type M001TV struct {
	Name     string
	XPubKey  []byte
	XSig     []byte
	Msg      []byte
	Expected int
}

// ---- helpers ----

func evalTV(name string, code []byte, msg []byte) EvalTV {
	e := ll.NewEval()
	err := e.EvalWithXmsg(code, msg)
	stack := make([]byte, len(e.Stack.S))
	copy(stack, e.Stack.S)
	return EvalTV{
		Name:        name,
		Code:        code,
		Msg:         msg,
		ExpectError: err != nil,
		ExpectStack: stack,
	}
}

func evalTVAsm(name string, build func(a *ll.Assembler), msg []byte) EvalTV {
	a := ll.Assembler{}
	build(&a)
	return evalTV(name, a.Code, msg)
}

func evalTVWithCtx(name string, code []byte, msg []byte, deviceID []byte) EvalTV {
	e := ll.NewEval()
	if len(deviceID) > 0 {
		e.Context = &ll.DeviceContext{DeviceID: deviceID}
	}
	err := e.EvalWithXmsg(code, msg)
	stack := make([]byte, len(e.Stack.S))
	copy(stack, e.Stack.S)
	return EvalTV{
		Name:        name,
		Code:        code,
		Msg:         msg,
		DeviceID:    deviceID,
		ExpectError: err != nil,
		ExpectStack: stack,
	}
}

func evalTVAsmWithCtx(name string, build func(a *ll.Assembler), msg []byte, deviceID []byte) EvalTV {
	a := ll.Assembler{}
	build(&a)
	return evalTVWithCtx(name, a.Code, msg, deviceID)
}

func m001TV(name string, xpubkey, xsig, msg []byte) M001TV {
	result := machines.RunMachine001(xpubkey, xsig, msg)
	expected := 0
	if result {
		expected = 1
	}
	return M001TV{Name: name, XPubKey: xpubkey, XSig: xsig, Msg: msg, Expected: expected}
}

func serializeXSig(build func(mc *machines.MachineCode)) []byte {
	mc := machines.MachineCode{}
	build(&mc)
	return mc.Serialize(machines.CodeTypeXSig)
}

func serializeXPubKey(build func(mc *machines.MachineCode)) []byte {
	mc := machines.MachineCode{}
	build(&mc)
	return mc.Serialize(machines.CodeTypeXPublicKey)
}

// ---- eval test generators ----

func arithmeticTests() []EvalTV {
	return []EvalTV{
		evalTVAsm("add_basic", func(a *ll.Assembler) {
			a.Append(ll.Push1(1)); a.Append(ll.Push1(42)); a.Append(ll.Add())
		}, nil),
		evalTVAsm("add_commutative", func(a *ll.Assembler) {
			a.Append(ll.Push1(42)); a.Append(ll.Push1(1)); a.Append(ll.Add())
		}, nil),
		evalTVAsm("mul_basic", func(a *ll.Assembler) {
			a.Append(ll.Push1(43)); a.Append(ll.Push1(3)); a.Append(ll.Mul())
		}, nil),
		evalTVAsm("add_then_mul", func(a *ll.Assembler) {
			a.Append(ll.Push1(1)); a.Append(ll.Push1(42)); a.Append(ll.Add())
			a.Append(ll.Push1(3)); a.Append(ll.Mul())
		}, nil),
		evalTVAsm("add_zero", func(a *ll.Assembler) {
			a.Append(ll.Push1(0)); a.Append(ll.Push1(42)); a.Append(ll.Add())
		}, nil),
		evalTVAsm("mul_zero", func(a *ll.Assembler) {
			a.Append(ll.Push1(0)); a.Append(ll.Push1(42)); a.Append(ll.Mul())
		}, nil),
		evalTVAsm("mul_one", func(a *ll.Assembler) {
			a.Append(ll.Push1(1)); a.Append(ll.Push1(42)); a.Append(ll.Mul())
		}, nil),
		evalTVAsm("mul_identity", func(a *ll.Assembler) {
			a.Append(ll.Push1(255)); a.Append(ll.Push1(1)); a.Append(ll.Mul())
		}, nil),
		evalTVAsm("chained_adds", func(a *ll.Assembler) {
			a.Append(ll.Push1(1)); a.Append(ll.Push1(2))
			a.Append(ll.Push1(3)); a.Append(ll.Push1(4))
			a.Append(ll.Add()); a.Append(ll.Add()); a.Append(ll.Add())
		}, nil),
	}
}

func overflowTests() []EvalTV {
	return []EvalTV{
		evalTVAsm("add_overflow_wrap", func(a *ll.Assembler) {
			a.Append(ll.Push1(200)); a.Append(ll.Push1(200)); a.Append(ll.Add())
		}, nil),
		evalTVAsm("add_overflow_ff_plus_1", func(a *ll.Assembler) {
			a.Append(ll.Push1(0xFF)); a.Append(ll.Push1(0x01)); a.Append(ll.Add())
		}, nil),
		evalTVAsm("add_overflow_ff_plus_ff", func(a *ll.Assembler) {
			a.Append(ll.Push1(0xFF)); a.Append(ll.Push1(0xFF)); a.Append(ll.Add())
		}, nil),
		evalTVAsm("mul_overflow_16x16", func(a *ll.Assembler) {
			a.Append(ll.Push1(16)); a.Append(ll.Push1(16)); a.Append(ll.Mul())
		}, nil),
		evalTVAsm("mul_overflow_ff_x2", func(a *ll.Assembler) {
			a.Append(ll.Push1(0xFF)); a.Append(ll.Push1(0x02)); a.Append(ll.Mul())
		}, nil),
		evalTVAsm("mul_overflow_128x2", func(a *ll.Assembler) {
			a.Append(ll.Push1(128)); a.Append(ll.Push1(2)); a.Append(ll.Mul())
		}, nil),
	}
}

func bitwiseTests() []EvalTV {
	return []EvalTV{
		evalTVAsm("and_basic", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x0F)); a.Append(ll.Push1(0x55)); a.Append(ll.And())
		}, nil),
		evalTVAsm("or_basic", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x0F)); a.Append(ll.Push1(0x55)); a.Append(ll.Or())
		}, nil),
		evalTVAsm("not_basic", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x55)); a.Append(ll.Not())
		}, nil),
		evalTVAsm("not_zero", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x00)); a.Append(ll.Not())
		}, nil),
		evalTVAsm("not_ff", func(a *ll.Assembler) {
			a.Append(ll.Push1(0xFF)); a.Append(ll.Not())
		}, nil),
		evalTVAsm("and_zero", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x00)); a.Append(ll.Push1(0xFF)); a.Append(ll.And())
		}, nil),
		evalTVAsm("and_ff", func(a *ll.Assembler) {
			a.Append(ll.Push1(0xFF)); a.Append(ll.Push1(0xFF)); a.Append(ll.And())
		}, nil),
		evalTVAsm("or_zero", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x00)); a.Append(ll.Push1(0x00)); a.Append(ll.Or())
		}, nil),
		evalTVAsm("or_ff", func(a *ll.Assembler) {
			a.Append(ll.Push1(0xFF)); a.Append(ll.Push1(0x00)); a.Append(ll.Or())
		}, nil),
		evalTVAsm("double_not", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x55)); a.Append(ll.Not()); a.Append(ll.Not())
		}, nil),
		evalTVAsm("not_then_and", func(a *ll.Assembler) {
			a.Append(ll.Push1(0x55)); a.Append(ll.Not())
			a.Append(ll.Push1(0xF0)); a.Append(ll.And())
		}, nil),
	}
}

func stackTests() []EvalTV {
	tests := []EvalTV{
		// Empty program
		evalTV("empty_program", []byte{}, nil),
		// Single push
		evalTVAsm("push_one", func(a *ll.Assembler) {
			a.Append(ll.Push1(1))
		}, nil),
		// Multiple pushes
		evalTVAsm("push_three", func(a *ll.Assembler) {
			a.Append(ll.Push1(1)); a.Append(ll.Push1(2)); a.Append(ll.Push1(3))
		}, nil),
		// Multi-byte push (assembler reverses bytes)
		evalTVAsm("push_multi_byte", func(a *ll.Assembler) {
			a.Append(ll.Push([]byte{0x01, 0x02, 0x03}))
		}, nil),
		// Two values left on stack
		evalTVAsm("two_values_remain", func(a *ll.Assembler) {
			a.Append(ll.Push1(10)); a.Append(ll.Push1(20))
		}, nil),
		// Push then partial consume
		evalTVAsm("push4_add1", func(a *ll.Assembler) {
			a.Append(ll.Push1(1)); a.Append(ll.Push1(2))
			a.Append(ll.Push1(3)); a.Append(ll.Push1(4))
			a.Append(ll.Add())
		}, nil),
	}

	// Stack at exactly 1024 (max)
	{
		// 4 * Push(255) + Push(4) = 1024
		code := []byte{}
		for i := 0; i < 4; i++ {
			code = append(code, 0x03, 0xFF) // OP_PUSH, 255
			for j := 0; j < 255; j++ {
				code = append(code, byte(j))
			}
		}
		code = append(code, 0x03, 0x04, 0x00, 0x01, 0x02, 0x03) // Push(4)
		tests = append(tests, evalTV("stack_exact_1024", code, nil))
	}

	// Stack overflow at 1025
	{
		code := []byte{}
		for i := 0; i < 4; i++ {
			code = append(code, 0x03, 0xFF) // OP_PUSH, 255
			for j := 0; j < 255; j++ {
				code = append(code, byte(j))
			}
		}
		code = append(code, 0x03, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04) // Push(5) → overflow
		tests = append(tests, evalTV("stack_overflow_1025", code, nil))
	}

	return tests
}

func pushEdgeTests() []EvalTV {
	return []EvalTV{
		// Push with length 0
		evalTV("push_zero_len", []byte{0x03, 0x00}, nil),
		// Push missing length byte
		evalTV("push_missing_len", []byte{0x03}, nil),
		// Push truncated data
		evalTV("push_truncated", []byte{0x03, 0x05, 0x01, 0x02}, nil),
		// Push exactly 255 bytes
		evalTV("push_255_bytes", func() []byte {
			code := []byte{0x03, 0xFF}
			for i := 0; i < 255; i++ {
				code = append(code, byte(i))
			}
			return code
		}(), nil),
		// Two consecutive pushes
		evalTV("push_two_consecutive", []byte{0x03, 0x01, 0xAA, 0x03, 0x01, 0xBB}, nil),
		// Push at very end of code (just opcode, no room for length)
		evalTV("push_at_end", []byte{0x03, 0x01, 0x42, 0x03}, nil),
	}
}

func errorTests() []EvalTV {
	return []EvalTV{
		// Underflow
		evalTV("add_empty_stack", []byte{0x01}, nil),
		evalTV("mul_empty_stack", []byte{0x02}, nil),
		evalTV("and_empty_stack", []byte{0x06}, nil),
		evalTV("or_empty_stack", []byte{0x07}, nil),
		evalTV("not_empty_stack", []byte{0x08}, nil),
		// One element only (needs two for binary ops)
		evalTV("add_one_element", []byte{0x03, 0x01, 0x42, 0x01}, nil),
		evalTV("mul_one_element", []byte{0x03, 0x01, 0x42, 0x02}, nil),
		evalTV("and_one_element", []byte{0x03, 0x01, 0x42, 0x06}, nil),
		evalTV("or_one_element", []byte{0x03, 0x01, 0x42, 0x07}, nil),
		// Unknown opcodes
		evalTV("unknown_opcode_0B", []byte{0x0B}, nil),
		evalTV("unknown_opcode_0C", []byte{0x0C}, nil),
		evalTV("unknown_opcode_FF", []byte{0xFF}, nil),
		evalTV("unknown_after_valid", []byte{0x03, 0x01, 0x42, 0x0B}, nil),
		// Sigverify on empty stack
		evalTV("sigverify_empty_stack", []byte{0x04}, nil),
		// Multisigverify on empty stack
		evalTV("multisigverify_empty_stack", []byte{0x05}, nil),
	}
}

func complexSequenceTests() []EvalTV {
	return []EvalTV{
		evalTVAsm("add_not", func(a *ll.Assembler) {
			a.Append(ll.Push1(5)); a.Append(ll.Push1(3)); a.Append(ll.Add()); a.Append(ll.Not())
		}, nil),
		evalTVAsm("and_or_chain", func(a *ll.Assembler) {
			a.Append(ll.Push1(0xFF)); a.Append(ll.Push1(0x0F)); a.Append(ll.And())
			a.Append(ll.Push1(0xF0)); a.Append(ll.Or())
		}, nil),
		evalTVAsm("mul_add_mix", func(a *ll.Assembler) {
			a.Append(ll.Push1(3)); a.Append(ll.Push1(4)); a.Append(ll.Mul())
			a.Append(ll.Push1(1)); a.Append(ll.Add())
		}, nil),
		evalTVAsm("all_ops", func(a *ll.Assembler) {
			a.Append(ll.Push1(10)); a.Append(ll.Push1(20)); a.Append(ll.Add())
			a.Append(ll.Push1(2)); a.Append(ll.Mul())
			a.Append(ll.Push1(0x0F)); a.Append(ll.And())
			a.Append(ll.Push1(0xF0)); a.Append(ll.Or())
			a.Append(ll.Not())
		}, nil),
		evalTVAsm("multi_byte_push_then_add", func(a *ll.Assembler) {
			a.Append(ll.Push([]byte{0x01, 0x02})) // stack: [0x02, 0x01]
			a.Append(ll.Add())                     // pop 0x01 and 0x02, push 0x03
		}, nil),
	}
}

func sigverifyEvalTests() []EvalTV {
	msg := []byte("test_sigverify")
	_, pk, sig := crypto.HelperVerifyData(msg)

	return []EvalTV{
		evalTVAsm("sigverify_valid", func(a *ll.Assembler) {
			a.Append(ll.Push(sig)); a.Append(ll.Push(pk)); a.Append(ll.SignatureVerify())
		}, msg),
		evalTVAsm("sigverify_wrong_msg", func(a *ll.Assembler) {
			a.Append(ll.Push(sig)); a.Append(ll.Push(pk)); a.Append(ll.SignatureVerify())
		}, []byte("wrong")),
		// Sigverify then arithmetic
		evalTVAsm("sigverify_then_not", func(a *ll.Assembler) {
			a.Append(ll.Push(sig)); a.Append(ll.Push(pk))
			a.Append(ll.SignatureVerify()); a.Append(ll.Not())
		}, msg),
	}
}

func equal32Tests() []EvalTV {
	id32 := make([]byte, 32)
	for i := range id32 {
		id32[i] = byte(i + 1)
	}
	id32diff := make([]byte, 32)
	copy(id32diff, id32)
	id32diff[31] = 0xFF

	return []EvalTV{
		evalTVAsm("equal32_match", func(a *ll.Assembler) {
			a.Append(ll.Push(id32))
			a.Append(ll.Push(id32))
			a.Append(ll.Equal32())
		}, nil),
		evalTVAsm("equal32_mismatch", func(a *ll.Assembler) {
			a.Append(ll.Push(id32))
			a.Append(ll.Push(id32diff))
			a.Append(ll.Equal32())
		}, nil),
		evalTVAsm("equal32_underflow", func(a *ll.Assembler) {
			a.Append(ll.Push(id32))
			a.Append(ll.Equal32())
		}, nil),
		evalTV("equal32_empty_stack", []byte{0x09}, nil),
		evalTVAsm("equal32_zeros", func(a *ll.Assembler) {
			zeros := make([]byte, 32)
			a.Append(ll.Push(zeros))
			a.Append(ll.Push(zeros))
			a.Append(ll.Equal32())
		}, nil),
		evalTVAsm("equal32_ff", func(a *ll.Assembler) {
			ff := make([]byte, 32)
			for i := range ff {
				ff[i] = 0xFF
			}
			a.Append(ll.Push(ff))
			a.Append(ll.Push(ff))
			a.Append(ll.Equal32())
		}, nil),
	}
}

func deviceIDTests() []EvalTV {
	deviceID := make([]byte, 32)
	for i := range deviceID {
		deviceID[i] = byte(i + 1)
	}

	diffID := make([]byte, 32)
	copy(diffID, deviceID)
	diffID[0] = 0xFF

	return []EvalTV{
		// DEVICEID + EQUAL32 with matching PUSH
		evalTVAsmWithCtx("deviceid_equal_match", func(a *ll.Assembler) {
			a.Append(ll.Push(deviceID))
			a.Append(ll.DeviceID())
			a.Append(ll.Equal32())
		}, nil, deviceID),
		// DEVICEID + EQUAL32 with mismatched PUSH
		evalTVAsmWithCtx("deviceid_equal_mismatch", func(a *ll.Assembler) {
			a.Append(ll.Push(diffID))
			a.Append(ll.DeviceID())
			a.Append(ll.Equal32())
		}, nil, deviceID),
		// DEVICEID without context → error
		evalTVAsm("deviceid_no_context", func(a *ll.Assembler) {
			a.Append(ll.DeviceID())
		}, nil),
		// Just DEVICEID with context (leaves 32 bytes on stack)
		evalTVAsmWithCtx("deviceid_push_only", func(a *ll.Assembler) {
			a.Append(ll.DeviceID())
		}, nil, deviceID),
	}
}

// ---- m001 test generators ----

func singleSigM001Tests() []M001TV {
	msg := []byte("yolo")
	_, pk, sig := crypto.HelperVerifyData(msg)

	xsig := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push(sig)) })
	xpk := serializeXPubKey(func(mc *machines.MachineCode) {
		mc.Append(ll.Push(pk)); mc.Append(ll.SignatureVerify())
	})

	return []M001TV{
		m001TV("m001_singlesig_valid", xpk, xsig, msg),
		m001TV("m001_singlesig_wrong_msg", xpk, xsig, []byte("wrong")),
	}
}

func multisigM001Tests() []M001TV {
	msg := []byte("multisig_test")
	_, pk1, sig1 := crypto.HelperVerifyData(msg)
	_, pk2, sig2 := crypto.HelperVerifyData(msg)
	_, pk3, sig3 := crypto.HelperVerifyData(msg)

	build2of3PK := func(pka, pkb, pkc []byte) []byte {
		return serializeXPubKey(func(mc *machines.MachineCode) {
			mc.Append(ll.Push(pka)); mc.Append(ll.Push(pkb)); mc.Append(ll.Push(pkc))
			mc.Append(ll.Push1(2)); mc.Append(ll.Push1(3)); mc.Append(ll.MultisigVerify())
		})
	}

	build2Sigs := func(sa, sb []byte) []byte {
		return serializeXSig(func(mc *machines.MachineCode) {
			mc.Append(ll.Push(sa)); mc.Append(ll.Push(sb))
		})
	}

	xpk := build2of3PK(pk1, pk2, pk3)

	var tests []M001TV

	// Valid 2-of-3 combinations
	tests = append(tests, m001TV("m001_2of3_sig12", xpk, build2Sigs(sig1, sig2), msg))
	tests = append(tests, m001TV("m001_2of3_sig21", xpk, build2Sigs(sig2, sig1), msg))
	tests = append(tests, m001TV("m001_2of3_sig13", xpk, build2Sigs(sig1, sig3), msg))
	tests = append(tests, m001TV("m001_2of3_sig23", xpk, build2Sigs(sig2, sig3), msg))

	// Duplicate sigs (should fail)
	tests = append(tests, m001TV("m001_2of3_dup_sig11", xpk, build2Sigs(sig1, sig1), msg))
	tests = append(tests, m001TV("m001_2of3_dup_sig22", xpk, build2Sigs(sig2, sig2), msg))

	// Wrong message
	tests = append(tests, m001TV("m001_2of3_wrong_msg", xpk, build2Sigs(sig1, sig2), []byte("bad")))

	// 1-of-1
	xpk1of1 := serializeXPubKey(func(mc *machines.MachineCode) {
		mc.Append(ll.Push(pk1)); mc.Append(ll.Push1(1)); mc.Append(ll.Push1(1))
		mc.Append(ll.MultisigVerify())
	})
	xsig1of1 := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push(sig1)) })
	tests = append(tests, m001TV("m001_1of1_valid", xpk1of1, xsig1of1, msg))

	// 3-of-3
	xpk3of3 := serializeXPubKey(func(mc *machines.MachineCode) {
		mc.Append(ll.Push(pk1)); mc.Append(ll.Push(pk2)); mc.Append(ll.Push(pk3))
		mc.Append(ll.Push1(3)); mc.Append(ll.Push1(3)); mc.Append(ll.MultisigVerify())
	})
	xsig3of3 := serializeXSig(func(mc *machines.MachineCode) {
		mc.Append(ll.Push(sig1)); mc.Append(ll.Push(sig2)); mc.Append(ll.Push(sig3))
	})
	tests = append(tests, m001TV("m001_3of3_valid", xpk3of3, xsig3of3, msg))

	// 3-of-3 with only 2 distinct
	xsig3of3dup := serializeXSig(func(mc *machines.MachineCode) {
		mc.Append(ll.Push(sig1)); mc.Append(ll.Push(sig2)); mc.Append(ll.Push(sig1))
	})
	tests = append(tests, m001TV("m001_3of3_only2distinct", xpk3of3, xsig3of3dup, msg))

	// Repeated public keys
	xpkRepeat := build2of3PK(pk1, pk1, pk3)
	tests = append(tests, m001TV("m001_2of3_repeated_pk_pass", xpkRepeat, build2Sigs(sig1, sig3), msg))
	tests = append(tests, m001TV("m001_2of3_repeated_pk_fail", xpkRepeat, build2Sigs(sig2, sig3), msg))

	return tests
}

func finalStackM001Tests() []M001TV {
	emptyXSig := serializeXSig(func(mc *machines.MachineCode) {})
	emptyXPK := serializeXPubKey(func(mc *machines.MachineCode) {})

	push1XSig := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push1(1)) })
	push0XSig := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push1(0)) })
	push2XSig := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push1(2)) })
	push11XSig := serializeXSig(func(mc *machines.MachineCode) {
		mc.Append(ll.Push1(1)); mc.Append(ll.Push1(1))
	})

	push1XPK := serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Push1(1)) })
	push0XPK := serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Push1(0)) })

	msg := []byte("test")

	return []M001TV{
		// Both empty → stack is [] → fail
		m001TV("m001_both_empty", emptyXPK, emptyXSig, msg),
		// xsig pushes [1], xpubkey empty → stack [1] → pass
		m001TV("m001_xsig_push1_xpk_empty", emptyXPK, push1XSig, msg),
		// xsig empty, xpubkey pushes [1] → stack [1] → pass
		m001TV("m001_xsig_empty_xpk_push1", push1XPK, emptyXSig, msg),
		// xsig pushes [0] → stack [0] → fail
		m001TV("m001_stack_zero", emptyXPK, push0XSig, msg),
		// xsig pushes [2] → stack [2] → fail
		m001TV("m001_stack_two", emptyXPK, push2XSig, msg),
		// xsig pushes [1,1] → stack has 2 elements → fail
		m001TV("m001_stack_two_elements", emptyXPK, push11XSig, msg),
		// xsig pushes [0], xpubkey pushes [0] → stack [0, 0] → fail
		m001TV("m001_two_zeros", push0XPK, push0XSig, msg),
	}
}

func phaseTransferM001Tests() []M001TV {
	msg := []byte("phase_test")

	// xsig pushes [1, 0], xpubkey does ADD → stack [1] → pass
	xsig1 := serializeXSig(func(mc *machines.MachineCode) {
		mc.Append(ll.Push1(1)); mc.Append(ll.Push1(0))
	})
	xpk1 := serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Add()) })

	// xsig pushes [0xFE], xpubkey does NOT → stack [0x01] → pass
	xsig2 := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push1(0xFE)) })
	xpk2 := serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Not()) })

	// xsig pushes [0xFF], xpubkey does NOT → stack [0x00] → fail
	xsig3 := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push1(0xFF)) })
	xpk3 := serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Not()) })

	// xsig pushes [3, 4], xpubkey does MUL, pushes [11], SUB→ test operand order
	// stack after xsig: [3, 4]. MUL pops a=4, b=3, pushes 12.
	xsig4 := serializeXSig(func(mc *machines.MachineCode) {
		mc.Append(ll.Push1(3)); mc.Append(ll.Push1(4))
	})
	xpk4 := serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Mul()) })

	// xsig pushes [0x01, 0xFF], xpubkey does AND → stack [0x01] → pass
	xsig5 := serializeXSig(func(mc *machines.MachineCode) {
		mc.Append(ll.Push1(0x01)); mc.Append(ll.Push1(0xFF))
	})
	xpk5 := serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.And()) })

	return []M001TV{
		m001TV("m001_phase_add", xpk1, xsig1, msg),
		m001TV("m001_phase_not_pass", xpk2, xsig2, msg),
		m001TV("m001_phase_not_fail", xpk3, xsig3, msg),
		m001TV("m001_phase_mul", xpk4, xsig4, msg),
		m001TV("m001_phase_and_pass", xpk5, xsig5, msg),
	}
}

func errorM001Tests() []M001TV {
	msg := []byte("msg")
	return []M001TV{
		m001TV("m001_empty_input", []byte{}, []byte{}, msg),
		m001TV("m001_garbage_prefix", []byte("garbage"), []byte("garbage"), msg),
		// Valid xsig, bad xpubkey prefix
		m001TV("m001_xpk_bad_prefix", []byte("garbage"),
			serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push1(1)) }), msg),
		// Valid xpubkey, bad xsig prefix
		m001TV("m001_xsig_bad_prefix",
			serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Push1(1)) }),
			[]byte("garbage"), msg),
		// Unknown opcode in xsig
		m001TV("m001_xsig_bad_opcode",
			serializeXPubKey(func(mc *machines.MachineCode) { mc.Append(ll.Push1(1)) }),
			func() []byte {
				mc := machines.MachineCode{}
				mc.Code = []byte{0xFF}
				return mc.Serialize(machines.CodeTypeXSig)
			}(), msg),
		// Unknown opcode in xpubkey
		m001TV("m001_xpk_bad_opcode",
			func() []byte {
				mc := machines.MachineCode{}
				mc.Code = []byte{0xFF}
				return mc.Serialize(machines.CodeTypeXPublicKey)
			}(),
			serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push1(1)) }), msg),
	}
}

// ---- random test generators ----

func randomSmartEvalTests(n int, seed int64) []EvalTV {
	rng := rand.New(rand.NewSource(seed))
	tests := make([]EvalTV, n)
	for i := 0; i < n; i++ {
		a := ll.Assembler{}
		depth := 0
		nOps := rng.Intn(20) + 1

		for j := 0; j < nOps; j++ {
			if depth < 2 || rng.Intn(3) == 0 {
				if rng.Intn(5) == 0 && depth+rng.Intn(5)+2 <= 200 {
					// Multi-byte push
					sz := rng.Intn(5) + 2
					data := make([]byte, sz)
					for k := range data {
						data[k] = byte(rng.Intn(256))
					}
					a.Append(ll.Push(data))
					depth += sz
				} else {
					a.Append(ll.Push1(rng.Intn(256)))
					depth++
				}
			} else {
				switch rng.Intn(6) {
				case 0:
					a.Append(ll.Add())
					depth--
				case 1:
					a.Append(ll.Mul())
					depth--
				case 2:
					a.Append(ll.And())
					depth--
				case 3:
					a.Append(ll.Or())
					depth--
				case 4:
					a.Append(ll.Not())
				case 5:
					if depth >= 64 {
						a.Append(ll.Equal32())
						depth -= 63 // pop 64, push 1
					} else {
						a.Append(ll.Push1(rng.Intn(256)))
						depth++
					}
				}
			}
		}
		tests[i] = evalTV(fmt.Sprintf("rand_smart_%d", i), a.Code, nil)
	}
	return tests
}

func randomDumbEvalTests(n int, seed int64) []EvalTV {
	rng := rand.New(rand.NewSource(seed))
	tests := make([]EvalTV, n)
	for i := 0; i < n; i++ {
		a := ll.Assembler{}
		nOps := rng.Intn(15) + 1
		for j := 0; j < nOps; j++ {
			switch rng.Intn(7) {
			case 0:
				a.Append(ll.Push1(rng.Intn(256)))
			case 1:
				a.Append(ll.Add())
			case 2:
				a.Append(ll.Mul())
			case 3:
				a.Append(ll.And())
			case 4:
				a.Append(ll.Or())
			case 5:
				a.Append(ll.Not())
			case 6:
				a.Append(ll.Equal32())
			}
		}
		tests[i] = evalTV(fmt.Sprintf("rand_dumb_%d", i), a.Code, nil)
	}
	return tests
}

func randomRawByteTests(n int, seed int64) []EvalTV {
	rng := rand.New(rand.NewSource(seed))
	tests := make([]EvalTV, n)
	for i := 0; i < n; i++ {
		sz := rng.Intn(50) + 1
		code := make([]byte, sz)
		for j := range code {
			code[j] = byte(rng.Intn(256))
		}
		tests[i] = evalTV(fmt.Sprintf("rand_raw_%d", i), code, nil)
	}
	return tests
}

func randomSingleSigM001Tests(n int, seed int64) []M001TV {
	rng := rand.New(rand.NewSource(seed))
	tests := make([]M001TV, n)
	for i := 0; i < n; i++ {
		msgLen := rng.Intn(64) + 1
		msg := make([]byte, msgLen)
		rng.Read(msg)

		_, pk, sig := crypto.HelperVerifyData(msg)

		xsig := serializeXSig(func(mc *machines.MachineCode) { mc.Append(ll.Push(sig)) })
		xpk := serializeXPubKey(func(mc *machines.MachineCode) {
			mc.Append(ll.Push(pk)); mc.Append(ll.SignatureVerify())
		})

		verifyMsg := msg
		if rng.Intn(3) == 0 {
			verifyMsg = []byte("wrong_message_for_random_test")
		}

		tests[i] = m001TV(fmt.Sprintf("rand_sig_%d", i), xpk, xsig, verifyMsg)
	}
	return tests
}

func randomMultisigM001Tests(n int, seed int64) []M001TV {
	rng := rand.New(rand.NewSource(seed))
	tests := make([]M001TV, n)
	for i := 0; i < n; i++ {
		msg := make([]byte, rng.Intn(32)+1)
		rng.Read(msg)

		nKeys := rng.Intn(3) + 1
		nMinValid := rng.Intn(nKeys) + 1

		type kp struct {
			pk, sig []byte
		}
		keys := make([]kp, nKeys)
		for k := 0; k < nKeys; k++ {
			_, pk, sig := crypto.HelperVerifyData(msg)
			keys[k] = kp{pk, sig}
		}

		// Decide what kind of xsig to build
		scenario := rng.Intn(4)
		xsig := serializeXSig(func(mc *machines.MachineCode) {
			switch scenario {
			case 0: // All valid sigs (pick first nMinValid)
				for s := 0; s < nMinValid; s++ {
					mc.Append(ll.Push(keys[s].sig))
				}
			case 1: // Duplicate sig
				if nMinValid > 0 {
					for s := 0; s < nMinValid; s++ {
						mc.Append(ll.Push(keys[0].sig)) // same sig repeated
					}
				}
			case 2: // Mix of valid sigs
				for s := 0; s < nMinValid; s++ {
					idx := rng.Intn(nKeys)
					mc.Append(ll.Push(keys[idx].sig))
				}
			case 3: // Valid sigs but we'll use wrong message
				for s := 0; s < nMinValid; s++ {
					mc.Append(ll.Push(keys[s].sig))
				}
			}
		})

		xpk := serializeXPubKey(func(mc *machines.MachineCode) {
			for k := 0; k < nKeys; k++ {
				mc.Append(ll.Push(keys[k].pk))
			}
			mc.Append(ll.Push1(nMinValid))
			mc.Append(ll.Push1(nKeys))
			mc.Append(ll.MultisigVerify())
		})

		verifyMsg := msg
		if scenario == 3 {
			verifyMsg = []byte("wrong_message")
		}

		tests[i] = m001TV(fmt.Sprintf("rand_multi_%d", i), xpk, xsig, verifyMsg)
	}
	return tests
}

// ---- output ----

func emitBytes(f *os.File, name string, data []byte) {
	if len(data) == 0 {
		fmt.Fprintf(f, "static const uint8_t %s[] = {0};\n", name)
	} else {
		fmt.Fprintf(f, "static const uint8_t %s[] = {", name)
		for i, b := range data {
			if i > 0 {
				fmt.Fprint(f, ",")
			}
			if i%16 == 0 {
				fmt.Fprint(f, "\n    ")
			}
			fmt.Fprintf(f, "0x%02x", b)
		}
		fmt.Fprint(f, "\n};\n")
	}
}

func main() {
	var evalTests []EvalTV
	var m001Tests []M001TV

	evalTests = append(evalTests, arithmeticTests()...)
	evalTests = append(evalTests, overflowTests()...)
	evalTests = append(evalTests, bitwiseTests()...)
	evalTests = append(evalTests, stackTests()...)
	evalTests = append(evalTests, pushEdgeTests()...)
	evalTests = append(evalTests, errorTests()...)
	evalTests = append(evalTests, complexSequenceTests()...)
	evalTests = append(evalTests, sigverifyEvalTests()...)
	evalTests = append(evalTests, equal32Tests()...)
	evalTests = append(evalTests, deviceIDTests()...)
	evalTests = append(evalTests, randomSmartEvalTests(500, 42)...)
	evalTests = append(evalTests, randomDumbEvalTests(200, 123)...)
	evalTests = append(evalTests, randomRawByteTests(200, 456)...)

	m001Tests = append(m001Tests, singleSigM001Tests()...)
	m001Tests = append(m001Tests, multisigM001Tests()...)
	m001Tests = append(m001Tests, finalStackM001Tests()...)
	m001Tests = append(m001Tests, phaseTransferM001Tests()...)
	m001Tests = append(m001Tests, errorM001Tests()...)
	m001Tests = append(m001Tests, randomSingleSigM001Tests(50, 789)...)
	m001Tests = append(m001Tests, randomMultisigM001Tests(50, 101)...)

	f, err := os.Create("c/test_vectors.h")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	fmt.Fprintln(f, "// Auto-generated by gen_test_vectors.go — do not edit")
	fmt.Fprintln(f, "#pragma once")
	fmt.Fprintln(f, "#include <stdint.h>")
	fmt.Fprintln(f, "#include <stddef.h>")
	fmt.Fprintln(f, "#include <string.h>")
	fmt.Fprintln(f, "")

	// Types
	fmt.Fprintln(f, "typedef struct {")
	fmt.Fprintln(f, "    const char *name;")
	fmt.Fprintln(f, "    const uint8_t *code; size_t code_len;")
	fmt.Fprintln(f, "    const uint8_t *msg; size_t msg_len;")
	fmt.Fprintln(f, "    int expect_error;")
	fmt.Fprintln(f, "    const uint8_t *expect_stack; size_t expect_stack_len;")
	fmt.Fprintln(f, "    const uint8_t *device_id; size_t device_id_len;")
	fmt.Fprintln(f, "} eval_tv_t;")
	fmt.Fprintln(f, "")
	fmt.Fprintln(f, "typedef struct {")
	fmt.Fprintln(f, "    const char *name;")
	fmt.Fprintln(f, "    const uint8_t *xpubkey; size_t xpubkey_len;")
	fmt.Fprintln(f, "    const uint8_t *xsig; size_t xsig_len;")
	fmt.Fprintln(f, "    const uint8_t *msg; size_t msg_len;")
	fmt.Fprintln(f, "    int expected;")
	fmt.Fprintln(f, "} m001_tv_t;")
	fmt.Fprintln(f, "")

	// Eval test data
	fmt.Fprintf(f, "// === %d Eval Tests ===\n\n", len(evalTests))
	for i, tv := range evalTests {
		emitBytes(f, fmt.Sprintf("et_%d_code", i), tv.Code)
		emitBytes(f, fmt.Sprintf("et_%d_msg", i), tv.Msg)
		if !tv.ExpectError {
			emitBytes(f, fmt.Sprintf("et_%d_stack", i), tv.ExpectStack)
		}
		if len(tv.DeviceID) > 0 {
			emitBytes(f, fmt.Sprintf("et_%d_devid", i), tv.DeviceID)
		}
		fmt.Fprintln(f)
	}

	// Eval test table
	fmt.Fprintln(f, "static const eval_tv_t eval_tests[] = {")
	for i, tv := range evalTests {
		expectErr := 0
		if tv.ExpectError {
			expectErr = 1
		}
		stackRef := fmt.Sprintf("et_%d_stack", i)
		stackLen := len(tv.ExpectStack)
		if tv.ExpectError {
			stackRef = "NULL"
			stackLen = 0
		}
		devRef := "NULL"
		devLen := 0
		if len(tv.DeviceID) > 0 {
			devRef = fmt.Sprintf("et_%d_devid", i)
			devLen = len(tv.DeviceID)
		}
		fmt.Fprintf(f, "    {\"%s\", et_%d_code, %d, et_%d_msg, %d, %d, %s, %d, %s, %d},\n",
			tv.Name, i, len(tv.Code), i, len(tv.Msg), expectErr, stackRef, stackLen, devRef, devLen)
	}
	fmt.Fprintln(f, "};")
	fmt.Fprintf(f, "#define NUM_EVAL_TESTS %d\n\n", len(evalTests))

	// M001 test data
	fmt.Fprintf(f, "// === %d Machine001 Tests ===\n\n", len(m001Tests))
	for i, tv := range m001Tests {
		emitBytes(f, fmt.Sprintf("mt_%d_xpk", i), tv.XPubKey)
		emitBytes(f, fmt.Sprintf("mt_%d_xsig", i), tv.XSig)
		emitBytes(f, fmt.Sprintf("mt_%d_msg", i), tv.Msg)
		fmt.Fprintln(f)
	}

	// M001 test table
	fmt.Fprintln(f, "static const m001_tv_t m001_tests[] = {")
	for i, tv := range m001Tests {
		fmt.Fprintf(f, "    {\"%s\", mt_%d_xpk, %d, mt_%d_xsig, %d, mt_%d_msg, %d, %d},\n",
			tv.Name, i, len(tv.XPubKey), i, len(tv.XSig), i, len(tv.Msg), tv.Expected)
	}
	fmt.Fprintln(f, "};")
	fmt.Fprintf(f, "#define NUM_M001_TESTS %d\n", len(m001Tests))

	fmt.Fprintf(os.Stderr, "Generated %d eval + %d m001 = %d total test vectors\n",
		len(evalTests), len(m001Tests), len(evalTests)+len(m001Tests))
}
