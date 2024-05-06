package account

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

type Account struct {
	index   uint64          // index in tree
	nonce   uint64          // number of transactions from this account
	balance fr.Element      // balance amount
	pubKey  eddsa.PublicKey // 2 parts of pubkey :- X, Y
}

var (
	// size of account in bytes
	// index ∥ nonce ∥ balance ∥ pubkeyX ∥ pubkeyY, each chunk is 32 bytes
	// 32 * 5 = 160 bytes
	AccountSizeInBytes = 160
)

func (acc *Account) Reset() {
	acc.index = 0
	acc.nonce = 0
	acc.balance.SetZero()
	acc.pubKey.A.X.SetZero()
	acc.pubKey.A.Y.SetZero()
}

func (acc *Account) Marshal() []byte {
	res := [160]byte{}

	// index is 64 bits i.e 8 bytes
	// we have 32 bytes reserved for index part. So lets append 8 bytes at end to avoid conversion error
	// 32 - 8 = 24
	binary.BigEndian.PutUint64(res[24:], acc.index)

	// simiar with nonce
	binary.BigEndian.PutUint64(res[56:], acc.nonce)

	buf := acc.balance.Bytes()
	copy(res[64:], buf[:])

	buf = acc.pubKey.A.Bytes()
	copy(res[96:], buf[:])

	buf = acc.pubKey.A.Y.Bytes()
	copy(res[128:], buf[:])

	return res[:]
}

func UnMarshal(acc *Account, accBytes []byte) error {
	if len(accBytes) != AccountSizeInBytes {
		return fmt.Errorf("invalid bytes: required %d bytes, but found %d bytes", AccountSizeInBytes, len(accBytes))
	}

	acc.index = binary.BigEndian.Uint64(accBytes[24:32])
	acc.nonce = binary.BigEndian.Uint64(accBytes[56:64])
	acc.balance.SetBytes(accBytes[64:96])
	acc.pubKey.A.X.SetBytes(accBytes[96:128])
	acc.pubKey.A.Y.SetBytes(accBytes[128:])

	return nil
}
