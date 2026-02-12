// +build ignore

// Differential tester: generates random programs at runtime, runs through both
// Go eval and C ceval binary, and compares results. Exits with error on any mismatch.
//
// Usage: go run ./c/run_differential.go [-n 10000] [-seed 42]
// (run from project root)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"os/exec"
	"strings"

	ll "github.com/oreparaz/xsig/internal/lowlevel"
	machines "github.com/oreparaz/xsig/internal/machine"
)

var (
	nTests = flag.Int("n", 10000, "number of eval tests")
	nM001  = flag.Int("m", 1000, "number of m001 tests")
	seed   = flag.Int64("seed", 0, "random seed (0 = time-based)")
	cevalBin = flag.String("ceval", "c/ceval", "path to ceval binary")
)

func main() {
	flag.Parse()

	if *seed != 0 {
		mrand.Seed(*seed)
	} else {
		mrand.Seed(mrand.Int63())
	}

	// Verify ceval binary exists
	if _, err := os.Stat(*cevalBin); err != nil {
		log.Fatalf("ceval binary not found at %s: %v", *cevalBin, err)
	}

	failures := 0

	fmt.Printf("Running %d eval differential tests...\n", *nTests)
	for i := 0; i < *nTests; i++ {
		if err := runEvalTest(i); err != nil {
			fmt.Printf("FAIL eval #%d: %s\n", i, err)
			failures++
			if failures > 20 {
				log.Fatalf("Too many failures, aborting")
			}
		}
	}

	fmt.Printf("Running %d m001 differential tests...\n", *nM001)
	for i := 0; i < *nM001; i++ {
		if err := runM001Test(i); err != nil {
			fmt.Printf("FAIL m001 #%d: %s\n", i, err)
			failures++
			if failures > 20 {
				log.Fatalf("Too many failures, aborting")
			}
		}
	}

	fmt.Printf("\nResults: %d failures out of %d tests\n", failures, *nTests+*nM001)
	if failures > 0 {
		os.Exit(1)
	}
}

// ---- helpers ----

func signMsg(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, key, hash[:])
}

func compressPK(key *ecdsa.PublicKey) []byte {
	return elliptic.MarshalCompressed(key.Curve, key.X, key.Y)
}

func serializeXSig(build func(a *ll.Assembler)) []byte {
	mc := &machines.MachineCode{}
	build(&mc.Assembler)
	return mc.Serialize(machines.CodeTypeXSig)
}

func serializeXPubKey(build func(a *ll.Assembler)) []byte {
	mc := &machines.MachineCode{}
	build(&mc.Assembler)
	return mc.Serialize(machines.CodeTypeXPublicKey)
}

// ---- eval tests ----

func runEvalTest(idx int) error {
	code, msg, deviceID := genEvalProgram()

	// Run Go
	goResult, goStack := evalGo(code, msg, deviceID)

	// Run C
	cResult, cStack, err := evalC(code, msg, deviceID)
	if err != nil {
		return fmt.Errorf("ceval exec error: %v (code=%x msg=%x devid=%x)", err, code, msg, deviceID)
	}

	if goResult != cResult {
		return fmt.Errorf("result mismatch: go=%s c=%s (code=%x msg=%x devid=%x)",
			goResult, cResult, code, msg, deviceID)
	}
	if goResult == "ok" && goStack != cStack {
		return fmt.Errorf("stack mismatch: go=%s c=%s (code=%x msg=%x devid=%x)",
			goStack, cStack, code, msg, deviceID)
	}
	return nil
}

func evalGo(code, msg, deviceID []byte) (result string, stack string) {
	e := ll.NewEval()
	if len(deviceID) > 0 {
		e.Context = &ll.DeviceContext{DeviceID: deviceID}
	}
	err := e.EvalWithXmsg(code, msg)
	if err != nil {
		return "error", ""
	}
	return "ok", hex.EncodeToString(e.Stack.S)
}

func evalC(code, msg, deviceID []byte) (result string, stack string, err error) {
	args := []string{"eval",
		hex.EncodeToString(code),
		hex.EncodeToString(msg)}
	if len(deviceID) > 0 {
		args = append(args, hex.EncodeToString(deviceID))
	}
	out, execErr := exec.Command(*cevalBin, args...).CombinedOutput()

	outStr := strings.TrimSpace(string(out))

	if execErr != nil {
		return "", "", fmt.Errorf("exit error: %v output: %s", execErr, outStr)
	}

	if outStr == "error" {
		return "error", "", nil
	}
	if strings.HasPrefix(outStr, "ok:") {
		return "ok", outStr[3:], nil
	}
	return "", "", fmt.Errorf("unexpected output: %s", outStr)
}

func genEvalProgram() (code []byte, msg []byte, deviceID []byte) {
	r := mrand.Intn(12)
	switch {
	case r < 3:
		c, m := genSmartEval()
		return c, m, nil
	case r < 5:
		c, m := genArithmeticChain()
		return c, m, nil
	case r < 7:
		c, m := genSigverifyEval()
		return c, m, nil
	case r < 8:
		c, m := genDumbEval()
		return c, m, nil
	case r < 9:
		c, m := genRawBytes()
		return c, m, nil
	case r < 10:
		return genEqual32Eval()
	default:
		return genDeviceIDEval()
	}
}

func genSmartEval() ([]byte, []byte) {
	a := &ll.Assembler{}
	nOps := mrand.Intn(20) + 1
	for i := 0; i < nOps; i++ {
		op := mrand.Intn(7)
		switch op {
		case 0:
			n := mrand.Intn(10) + 1
			buf := make([]byte, n)
			for j := range buf {
				buf[j] = byte(mrand.Intn(256))
			}
			a.Append(ll.Push(buf))
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
	msg := make([]byte, mrand.Intn(32))
	for i := range msg {
		msg[i] = byte(mrand.Intn(256))
	}
	return a.Code, msg
}

func genArithmeticChain() ([]byte, []byte) {
	a := &ll.Assembler{}
	nPush := mrand.Intn(4) + 2
	for i := 0; i < nPush; i++ {
		a.Append(ll.Push1(mrand.Intn(256)))
	}
	nOps := mrand.Intn(nPush) + 1
	for i := 0; i < nOps; i++ {
		fns := []func() ll.Instruction{ll.Add, ll.Mul, ll.And, ll.Or}
		a.Append(fns[mrand.Intn(len(fns))]())
	}
	return a.Code, nil
}

func genSigverifyEval() ([]byte, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := make([]byte, 16+mrand.Intn(48))
	rand.Read(msg)

	pk := compressPK(&key.PublicKey)
	sig, err := signMsg(key, msg)
	if err != nil {
		return genArithmeticChain()
	}

	a := &ll.Assembler{}
	a.Append(ll.Push(sig))
	a.Append(ll.Push(pk))
	a.Append(ll.SignatureVerify())

	// Sometimes corrupt the message
	if mrand.Intn(3) == 0 {
		msg[0] ^= 0xff
	}

	return a.Code, msg
}

func genDumbEval() ([]byte, []byte) {
	a := &ll.Assembler{}
	nOps := mrand.Intn(15) + 1
	for i := 0; i < nOps; i++ {
		r := mrand.Intn(7)
		switch r {
		case 0:
			n := mrand.Intn(5) + 1
			buf := make([]byte, n)
			for j := range buf {
				buf[j] = byte(mrand.Intn(256))
			}
			a.Append(ll.Push(buf))
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
	return a.Code, nil
}

func genRawBytes() ([]byte, []byte) {
	n := mrand.Intn(64)
	code := make([]byte, n)
	for i := range code {
		code[i] = byte(mrand.Intn(256))
	}
	msg := make([]byte, mrand.Intn(16))
	for i := range msg {
		msg[i] = byte(mrand.Intn(256))
	}
	return code, msg
}

func genEqual32Eval() ([]byte, []byte, []byte) {
	a := &ll.Assembler{}

	// Push two 32-byte values, sometimes matching
	val1 := make([]byte, 32)
	for i := range val1 {
		val1[i] = byte(mrand.Intn(256))
	}
	val2 := make([]byte, 32)
	if mrand.Intn(2) == 0 {
		copy(val2, val1) // match
	} else {
		for i := range val2 {
			val2[i] = byte(mrand.Intn(256))
		}
	}

	a.Append(ll.Push(val1))
	a.Append(ll.Push(val2))
	a.Append(ll.Equal32())

	return a.Code, nil, nil
}

func genDeviceIDEval() ([]byte, []byte, []byte) {
	deviceID := make([]byte, 32)
	for i := range deviceID {
		deviceID[i] = byte(mrand.Intn(256))
	}

	a := &ll.Assembler{}

	switch mrand.Intn(3) {
	case 0:
		// PUSH(deviceID) DEVICEID EQUAL32 → should be 1
		a.Append(ll.Push(deviceID))
		a.Append(ll.DeviceID())
		a.Append(ll.Equal32())
	case 1:
		// PUSH(random) DEVICEID EQUAL32 → usually 0
		other := make([]byte, 32)
		for i := range other {
			other[i] = byte(mrand.Intn(256))
		}
		a.Append(ll.Push(other))
		a.Append(ll.DeviceID())
		a.Append(ll.Equal32())
	case 2:
		// Just DEVICEID (leaves 32 bytes on stack)
		a.Append(ll.DeviceID())
	}

	return a.Code, nil, deviceID
}

// ---- m001 tests ----

func runM001Test(idx int) error {
	xpubkey, xsig, msg, deviceID := genM001Input()

	// Run Go
	goResult := m001Go(xpubkey, xsig, msg, deviceID)

	// Run C
	cResult, err := m001C(xpubkey, xsig, msg, deviceID)
	if err != nil {
		return fmt.Errorf("ceval m001 exec error: %v", err)
	}

	if goResult != cResult {
		return fmt.Errorf("m001 mismatch: go=%d c=%d (xpk=%x xsig=%x msg=%x devid=%x)",
			goResult, cResult, xpubkey, xsig, msg, deviceID)
	}
	return nil
}

func m001Go(xpubkey, xsig, msg, deviceID []byte) int {
	var ctx *ll.DeviceContext
	if len(deviceID) > 0 {
		ctx = &ll.DeviceContext{DeviceID: deviceID}
	}
	if machines.RunMachine001WithContext(xpubkey, xsig, msg, ctx) {
		return 1
	}
	return 0
}

func m001C(xpubkey, xsig, msg, deviceID []byte) (int, error) {
	args := []string{"m001",
		hex.EncodeToString(xpubkey),
		hex.EncodeToString(xsig),
		hex.EncodeToString(msg)}
	if len(deviceID) > 0 {
		args = append(args, hex.EncodeToString(deviceID))
	}
	out, execErr := exec.Command(*cevalBin, args...).CombinedOutput()

	outStr := strings.TrimSpace(string(out))

	if execErr != nil {
		return 0, fmt.Errorf("exit error: %v output: %s", execErr, outStr)
	}

	if outStr == "1" {
		return 1, nil
	}
	return 0, nil
}

func genM001Input() (xpubkey, xsig, msg, deviceID []byte) {
	r := mrand.Intn(7)
	switch {
	case r < 2:
		xpk, xs, m := genValidSingleSig()
		return xpk, xs, m, nil
	case r < 3:
		xpk, xs, m := genValidMultisig()
		return xpk, xs, m, nil
	case r < 4:
		xpk, xs, m := genCorruptedSingleSig()
		return xpk, xs, m, nil
	case r < 5:
		xpk, xs, m := genRandomM001()
		return xpk, xs, m, nil
	case r < 6:
		xpk, xs, m := genRawM001()
		return xpk, xs, m, nil
	default:
		return genDeviceIDM001()
	}
}

func genValidSingleSig() ([]byte, []byte, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := make([]byte, 16+mrand.Intn(48))
	rand.Read(msg)

	pk := compressPK(&key.PublicKey)
	sig, err := signMsg(key, msg)
	if err != nil {
		return nil, nil, msg
	}

	xpubkey := serializeXPubKey(func(a *ll.Assembler) {
		a.Append(ll.Push(pk))
		a.Append(ll.SignatureVerify())
	})

	xsigSer := serializeXSig(func(a *ll.Assembler) {
		a.Append(ll.Push(sig))
	})

	return xpubkey, xsigSer, msg
}

func genValidMultisig() ([]byte, []byte, []byte) {
	msg := make([]byte, 16+mrand.Intn(48))
	rand.Read(msg)

	nKeys := 2 + mrand.Intn(2) // 2 or 3
	nMin := 1 + mrand.Intn(nKeys)

	keys := make([]*ecdsa.PrivateKey, nKeys)
	pks := make([][]byte, nKeys)
	for i := range keys {
		keys[i], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pks[i] = compressPK(&keys[i].PublicKey)
	}

	sigs := make([][]byte, nMin)
	for i := 0; i < nMin; i++ {
		sig, err := signMsg(keys[i], msg)
		if err != nil {
			return nil, nil, msg
		}
		sigs[i] = sig
	}

	xpubkey := serializeXPubKey(func(a *ll.Assembler) {
		for _, pk := range pks {
			a.Append(ll.Push(pk))
		}
		a.Append(ll.Push1(nMin))
		a.Append(ll.Push1(nKeys))
		a.Append(ll.MultisigVerify())
	})

	xsigSer := serializeXSig(func(a *ll.Assembler) {
		for _, sig := range sigs {
			a.Append(ll.Push(sig))
		}
	})

	return xpubkey, xsigSer, msg
}

func genCorruptedSingleSig() ([]byte, []byte, []byte) {
	xpubkey, xsig, msg := genValidSingleSig()

	switch mrand.Intn(3) {
	case 0:
		if len(msg) > 0 {
			msg[mrand.Intn(len(msg))] ^= byte(1 + mrand.Intn(255))
		}
	case 1:
		if len(xsig) > 6 {
			idx := 6 + mrand.Intn(len(xsig)-6)
			xsig[idx] ^= byte(1 + mrand.Intn(255))
		}
	case 2:
		if len(xpubkey) > 6 {
			idx := 6 + mrand.Intn(len(xpubkey)-6)
			xpubkey[idx] ^= byte(1 + mrand.Intn(255))
		}
	}
	return xpubkey, xsig, msg
}

func genRandomM001() ([]byte, []byte, []byte) {
	xpkCode := make([]byte, mrand.Intn(100))
	for i := range xpkCode {
		xpkCode[i] = byte(mrand.Intn(256))
	}
	xsigCode := make([]byte, mrand.Intn(100))
	for i := range xsigCode {
		xsigCode[i] = byte(mrand.Intn(256))
	}
	msg := make([]byte, mrand.Intn(32))
	for i := range msg {
		msg[i] = byte(mrand.Intn(256))
	}

	xpubkey := serializeXPubKey(func(a *ll.Assembler) {
		a.Code = xpkCode
	})
	xsigSer := serializeXSig(func(a *ll.Assembler) {
		a.Code = xsigCode
	})
	return xpubkey, xsigSer, msg
}

func genRawM001() ([]byte, []byte, []byte) {
	xpk := make([]byte, mrand.Intn(64))
	for i := range xpk {
		xpk[i] = byte(mrand.Intn(256))
	}
	xsig := make([]byte, mrand.Intn(64))
	for i := range xsig {
		xsig[i] = byte(mrand.Intn(256))
	}
	msg := make([]byte, mrand.Intn(32))
	for i := range msg {
		msg[i] = byte(mrand.Intn(256))
	}
	return xpk, xsig, msg
}

func genDeviceIDM001() ([]byte, []byte, []byte, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := make([]byte, 16+mrand.Intn(48))
	rand.Read(msg)

	pk := compressPK(&key.PublicKey)
	sig, err := signMsg(key, msg)
	if err != nil {
		return nil, nil, msg, nil
	}

	deviceID := make([]byte, 32)
	for i := range deviceID {
		deviceID[i] = byte(mrand.Intn(256))
	}

	// xsig pushes the signature
	xsigSer := serializeXSig(func(a *ll.Assembler) {
		a.Append(ll.Push(sig))
	})

	// xpubkey: PUSH(deviceID) DEVICEID EQUAL32 PUSH(pk) SIGVERIFY AND
	// This checks both device ID and signature
	xpubkey := serializeXPubKey(func(a *ll.Assembler) {
		a.Append(ll.Push(deviceID))
		a.Append(ll.DeviceID())
		a.Append(ll.Equal32())
		a.Append(ll.Push(pk))
		a.Append(ll.SignatureVerify())
		a.Append(ll.And())
	})

	// Sometimes use a wrong device ID
	testDeviceID := deviceID
	if mrand.Intn(3) == 0 {
		testDeviceID = make([]byte, 32)
		rand.Read(testDeviceID)
	}

	return xpubkey, xsigSer, msg, testDeviceID
}
