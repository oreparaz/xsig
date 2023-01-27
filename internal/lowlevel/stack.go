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
