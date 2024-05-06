package account

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccount(t *testing.T) {
	acc := Account{}
	acc.Reset()
	accBytes := acc.Marshal()

	var acc1 Account
	err := UnMarshal(&acc1, accBytes)

	assert.NoError(t, err)
	assert.Equal(t, acc, acc1)

	var acc2 Account
	accBytes = []byte{1, 2}
	err = UnMarshal(&acc2, accBytes)

	assert.ErrorContains(t, err, "invalid bytes")

}
