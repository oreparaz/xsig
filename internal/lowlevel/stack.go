package lowlevel

import (
	"fmt"
	"github.com/pkg/errors"
)

type Stack struct {
	S []uint8
}

func (s *Stack) IsEmpty() bool {
	return len(s.S) == 0
}

func (s *Stack) Push(x uint8) error {
	// TODO implement max size check
	s.S = append(s.S, x)
	return nil
}

func (s *Stack) PushBytes(buf []byte) error {
	for _, x := range buf {
		err := s.Push(x)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stack) Pop() (uint8, error) {
	if s.IsEmpty() {
		return 0, errors.New("stack underflow")
	}
	i := len(s.S) - 1
	x := (s.S)[i]
	s.S = (s.S)[:i]
	return x, nil
}

func (s *Stack) Pop2() (uint8, uint8, error) {
	a, err := s.Pop()
	if err != nil {
		return 0, 0, errors.Wrapf(err, "Pop2")
	}
	b, err := s.Pop()
	if err != nil {
		return 0, 0, errors.Wrapf(err, "Pop2")
	}
	return a, b, nil
}

// PopPublicKey pops a NIST-P256 (aka secp256r1) public key from the stack.
// We assume they are encoded according to ANSI X9.63 (uncompressed):
// 04 || X || Y where X and Y are 32 bytes.
// This function performs no point validation, and does *not* fully implement 2.3.4
// (OctetString-to-EllipticCurvePoint) from https://www.secg.org/SEC1-Ver-1.0.pdf
func (s *Stack) PopPublicKey() ([]byte, error) {
	var publicKey []byte
	for i:=0; i<65; i++ {
		val, err := s.Pop()
		if err != nil { return nil, errors.Wrapf(err, "PopPublicKey")}
		publicKey = append(publicKey, val)
	}
	if publicKey[0] != 0x04 {
		return nil, errors.New("unknown public key format")
	}
	return publicKey, nil
}

// PopSignature pops a ASN.1 encoded ECDSA signature. This function does not
// check if the signature is a proper ASN.1 encoding, it just does some light
// sanity check.
func (s *Stack) PopSignature() ([]byte, error) {
	// We don't want a full ASN.1 parser here, but we need to know how many bytes
	// we should pop from the stack. So we need to minimally parse the ASN.1 signature.
	//
	// The ASN.1 DER-encoded signature consists of: 0x30 || L1 || 0x02 || L2 || R || 0x02 || L3 || S
	// where
	// - 0x30 ASN.1 tag value for SEQUENCE
	// - L1 is the length of everything that follows
	// - 0x02 ASN.1 tag value for INTEGER
	// - L2 length of R
	// - R integer value
	// - L3 length of S
	// - S
	//
	// We're not interested in parsing beyond L1, but we do need to parse L1. So that's what we do.
	//
	//       ECDSASignature ::= SEQUENCE {
	//           r   INTEGER,
	//           s   INTEGER
	//      }
	var sig []byte
	marker, err := s.Pop()
	if err != nil {
		return nil, errors.Wrapf(err, "underflow")
	}
	if marker != 0x30 {
		return nil, errors.New(fmt.Sprintf("marker %d sig not valid DER encoding", marker))
	}
	sig = append(sig, marker)

	sigLen, err := s.Pop()
	if err != nil {
		return nil, errors.Wrapf(err, "underflow")
	}

	sig = append(sig, sigLen)
	for i:=0; i < int(sigLen); i++ {
		val, err := s.Pop()
		if err != nil {
			return nil, errors.Wrapf(err, "underflow")
		}
		sig = append(sig, val)
	}

	return sig, nil
}
