package transfer

import (
	"ZK-Rollup/signature"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/stretchr/testify/assert"
)

func TestTransferSignature(t *testing.T) {
	privKey1, pubKey1 := signature.GenerateKeys(1)
	privKey2, pubKey2 := signature.GenerateKeys(2)

	transferTx := Transfer{
		Nonce:          1,
		Amount:         fr.NewElement(10),
		SenderPubKey:   pubKey1,
		ReceiverPubKey: pubKey2,
		Signature:      eddsa.Signature{},
	}

	hFunc := mimc.NewMiMC()

	transferTx.SetSign(hFunc, privKey2)
	verified, err := transferTx.VerifySignature(hFunc)
	assert.Equal(t, verified, false)
	assert.NoError(t, err)

	transferTx.SetSign(hFunc, privKey1)
	verified, err = transferTx.VerifySignature(hFunc)
	assert.Equal(t, verified, true)
	assert.NoError(t, err)
}
