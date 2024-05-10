package account

import (
	"ZK-Rollup/signature"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccount(t *testing.T) {
	_, randomPubkey := signature.GenerateKeys(1)

	var acc Account
	acc.Reset()
	acc.PubKey = randomPubkey

	accBytes := acc.Marshal()

	var acc1 Account
	err := UnMarshal(&acc1, accBytes)

	assert.NoError(t, err)
	assert.Equal(t, acc.PubKey.A.X, acc1.PubKey.A.X)

	var acc2 Account
	accBytes = []byte{1, 2}
	err = UnMarshal(&acc2, accBytes)

	fmt.Println(acc.PubKey.A.X, acc.PubKey.A.X)
	assert.ErrorContains(t, err, "invalid bytes")

}
