package lowlevel

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStack_1(t *testing.T) {
	s := Stack{}

	assert.True(t, s.IsEmpty())

	err := s.Push(1)
	assert.Nil(t, err)

	err = s.Push(42)
	assert.Nil(t, err)

	assert.False(t, s.IsEmpty())

	v1, err := s.Pop()
	assert.Nil(t, err)
	assert.Equal(t, v1, uint8(42))

	v2, err := s.Pop()
	assert.Nil(t, err)
	assert.Equal(t, v2, uint8(1))

	_, err = s.Pop()
	assert.NotNil(t, err)
}
