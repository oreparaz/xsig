// +build ignore

// Generates seed corpus files for the fuzzers from real test vectors.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oreparaz/xsig/internal/crypto"
	ll "github.com/oreparaz/xsig/internal/lowlevel"
	machines "github.com/oreparaz/xsig/internal/machine"
)

func writeCorpus(dir, name string, data []byte) {
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, name)
	os.WriteFile(path, data, 0644)
	fmt.Printf("  %s (%d bytes)\n", path, len(data))
}

// Encode a machine001 fuzz input: [xsig_len][msg_len][xsig][msg][xpubkey]
func encodeMachine001Input(xsig, msg, xpubkey []byte) []byte {
	if len(xsig) > 255 || len(msg) > 255 {
		panic("too long")
	}
	out := []byte{byte(len(xsig)), byte(len(msg))}
	out = append(out, xsig...)
	out = append(out, msg...)
	out = append(out, xpubkey...)
	return out
}

// Encode an eval fuzz input: [msg_len_nibble][msg][code]
func encodeEvalInput(msg, code []byte) []byte {
	if len(msg) > 15 {
		panic("msg too long for eval fuzz format")
	}
	out := []byte{byte(len(msg))}
	out = append(out, msg...)
	out = append(out, code...)
	return out
}

func main() {
	fmt.Println("Generating seed corpus...")

	// --- machine001 corpus ---
	mdir := "c/corpus/machine001"

	// Single sig
	msg1 := []byte("yolo")
	_, pk1, sig1 := crypto.HelperVerifyData(msg1)
	a1 := machines.MachineCode{}
	a1.Append(ll.Push(sig1))
	xsig1 := a1.Serialize(machines.CodeTypeXSig)
	b1 := machines.MachineCode{}
	b1.Append(ll.Push(pk1))
	b1.Append(ll.SignatureVerify())
	xpk1 := b1.Serialize(machines.CodeTypeXPublicKey)
	writeCorpus(mdir, "single_sig", encodeMachine001Input(xsig1, msg1, xpk1))

	// 2-of-3 multisig
	msg3 := []byte("yolo")
	_, pk3a, sig3a := crypto.HelperVerifyData(msg3)
	_, pk3b, sig3b := crypto.HelperVerifyData(msg3)
	_, pk3c, _ := crypto.HelperVerifyData(msg3)
	a3 := machines.MachineCode{}
	a3.Append(ll.Push(sig3a))
	a3.Append(ll.Push(sig3b))
	xsig3 := a3.Serialize(machines.CodeTypeXSig)
	b3 := machines.MachineCode{}
	b3.Append(ll.Push(pk3a))
	b3.Append(ll.Push(pk3b))
	b3.Append(ll.Push(pk3c))
	b3.Append(ll.Push1(2))
	b3.Append(ll.Push1(3))
	b3.Append(ll.MultisigVerify())
	xpk3 := b3.Serialize(machines.CodeTypeXPublicKey)
	writeCorpus(mdir, "multisig_2of3", encodeMachine001Input(xsig3, msg3, xpk3))

	// Empty / garbage
	writeCorpus(mdir, "empty", encodeMachine001Input([]byte{}, []byte{}, []byte{}))
	writeCorpus(mdir, "garbage", encodeMachine001Input([]byte("garbage"), []byte("msg"), []byte("garbage")))

	// Valid prefix, unknown opcode
	mc := machines.MachineCode{}
	mc.Code = []byte{0xFF}
	writeCorpus(mdir, "bad_opcode_xsig", encodeMachine001Input(
		mc.Serialize(machines.CodeTypeXSig), []byte("msg"),
		b1.Serialize(machines.CodeTypeXPublicKey)))

	// --- eval corpus ---
	edir := "c/corpus/eval"

	// Arithmetic: push 1, push 42, add → 43
	asm := ll.Assembler{}
	asm.Append(ll.Push1(1))
	asm.Append(ll.Push1(42))
	asm.Append(ll.Add())
	writeCorpus(edir, "add", encodeEvalInput([]byte{}, asm.Code))

	// push 1, push 42, add, push 3, mul → 129
	asm = ll.Assembler{}
	asm.Append(ll.Push1(1))
	asm.Append(ll.Push1(42))
	asm.Append(ll.Add())
	asm.Append(ll.Push1(3))
	asm.Append(ll.Mul())
	writeCorpus(edir, "add_mul", encodeEvalInput([]byte{}, asm.Code))

	// Bitwise
	asm = ll.Assembler{}
	asm.Append(ll.Push1(0x0F))
	asm.Append(ll.Push1(0x55))
	asm.Append(ll.And())
	writeCorpus(edir, "and", encodeEvalInput([]byte{}, asm.Code))

	asm = ll.Assembler{}
	asm.Append(ll.Push1(0x55))
	asm.Append(ll.Not())
	writeCorpus(edir, "not", encodeEvalInput([]byte{}, asm.Code))

	// Sigverify with message
	msgE := []byte("test")
	_, pkE, sigE := crypto.HelperVerifyData(msgE)
	asm = ll.Assembler{}
	asm.Append(ll.Push(sigE))
	asm.Append(ll.Push(pkE))
	asm.Append(ll.SignatureVerify())
	writeCorpus(edir, "sigverify", encodeEvalInput(msgE, asm.Code))

	// --- der corpus ---
	ddir := "c/corpus/der"

	// Valid DER signatures from real signing
	for i := 0; i < 5; i++ {
		_, _, sig := crypto.HelperVerifyData([]byte(fmt.Sprintf("msg%d", i)))
		writeCorpus(ddir, fmt.Sprintf("valid_%d", i), sig)
	}

	// Minimal DER
	writeCorpus(ddir, "minimal", []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})

	// Edge: r with leading zero
	_ = sha256.New() // just to use the import
	writeCorpus(ddir, "empty", []byte{})
	writeCorpus(ddir, "just_tag", []byte{0x30})
	writeCorpus(ddir, "truncated", []byte{0x30, 0x44, 0x02, 0x20})

	fmt.Println("Done.")
}
