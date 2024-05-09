package transfer

import (
	"ZK-Rollup/signature"
	"encoding/binary"
	"hash"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

type Transfer struct {
	Nonce          uint64
	Amount         fr.Element
	SenderPubKey   eddsa.PublicKey
	ReceiverPubKey eddsa.PublicKey
	Signature      eddsa.Signature
}

func NewTransfer(amount uint64, from, to eddsa.PublicKey, nonce uint64) Transfer {
	var t Transfer
	t.Amount.SetUint64(amount)
	t.SenderPubKey = from
	t.ReceiverPubKey = to
	t.Nonce = nonce

	return t
}

func (t *Transfer) SetSign(hFunc hash.Hash, privateKey eddsa.PrivateKey) {
	t.Signature = t.Sign(hFunc, privateKey)
}

func (t *Transfer) Sign(hFunc hash.Hash, privateKey eddsa.PrivateKey) eddsa.Signature {

	msg := t.Message(hFunc)
	return signature.Sign(msg, privateKey, hFunc)
}

func (t *Transfer) Message(hFunc hash.Hash) []byte {
	hFunc.Reset()
	buf := make([]byte, 8)

	// Convert uint64 to bytes
	binary.BigEndian.PutUint64(buf, t.Nonce)
	hFunc.Write(buf)

	buf1 := t.Amount.Bytes()
	hFunc.Write(buf1[:])

	buf1 = t.SenderPubKey.A.X.Bytes()
	hFunc.Write(buf1[:])

	buf1 = t.SenderPubKey.A.Y.Bytes()
	hFunc.Write(buf1[:])

	buf1 = t.ReceiverPubKey.A.X.Bytes()
	hFunc.Write(buf1[:])

	buf1 = t.ReceiverPubKey.A.Y.Bytes()
	hFunc.Write(buf1[:])

	hashSum := hFunc.Sum(nil)
	return hashSum
}

func (t *Transfer) VerifySignature(hFunc hash.Hash) (bool, error) {
	msg := t.Message(hFunc)
	return signature.Verify(msg, t.SenderPubKey, t.Signature.Bytes(), hFunc)
}
