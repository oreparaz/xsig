package lowlevel

import (
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

func (s *Stack) Pop() (uint8, error) {
	if s.IsEmpty() {
		return 0, errors.New("stack underflow")
	}
	i := len(s.S) - 1
	x := (s.S)[i]
	s.S = (s.S)[:i]
	return x, nil
}
