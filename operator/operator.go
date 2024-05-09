package operator

import (
	"ZK-Rollup/account"
	"ZK-Rollup/circuit"
	"ZK-Rollup/modules/transfer"
	"ZK-Rollup/signature"
	"bytes"
	"errors"
	"hash"
	"log"
	"log/slog"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/std/accumulator/merkle"
)

var hFunc = mimc.NewMiMC()

var BatchSize = 10

type Queue struct {
	listTransfers chan transfer.Transfer
}

func NewQueue(circuitBatchSize int) Queue {
	resChan := make(chan transfer.Transfer, circuitBatchSize)
	return Queue{
		listTransfers: resChan,
	}
}

type Operator struct {
	State      []byte            // list of account bytes appended
	StateHash  []byte            // hash of account bytes appended
	AccountMap map[string]uint64 // pubkey to index map
	nbAccounts int               // number of accounts
	hFunc      hash.Hash         // hash function used
	queue      Queue             // channel which recieves transfer request
	batch      int               // tx count?
	witnesses  circuit.Circuit   // circuit
}

func NewOperator(nbAccounts int) Operator {
	state := make([]byte, nbAccounts*account.AccountSizeInBytes)
	hashState := make([]byte, nbAccounts*hFunc.Size())

	for i := 0; i < nbAccounts; i++ {
		hFunc.Reset()
		accountBytes := state[account.AccountSizeInBytes*i : account.AccountSizeInBytes*(i+1)]
		hFunc.Write(accountBytes)
		accountHash := hFunc.Sum(nil)
		copy(hashState[hFunc.Size()*i:hFunc.Size()*(i+1)], accountHash)
	}

	accountsMap := make(map[string]uint64)
	queue := NewQueue(BatchSize)
	circuit := circuit.Circuit{}

	return Operator{
		State:      state,
		StateHash:  hashState,
		nbAccounts: nbAccounts,
		hFunc:      hFunc,
		queue:      queue,
		batch:      0,
		AccountMap: accountsMap,
		witnesses:  circuit,
	}
}

func (o *Operator) ReadAccount(i uint64) account.Account {
	accountBytes := o.State[account.AccountSizeInBytes*int(i) : (int(i)+1)*account.AccountSizeInBytes]
	var acc account.Account
	if err := account.UnMarshal(&acc, accountBytes); err != nil {
		log.Fatal(err)
	}
	return acc
}

func (o *Operator) UpdateState(t transfer.Transfer, numTransfer int) error {

	senderpubkeyBytes := t.SenderPubKey.A.X.Bytes()
	senderKey := string(senderpubkeyBytes[:])
	sender, err := o.VerifyAndGetAccount(senderKey)
	if err != nil {
		return err
	}

	receiverpubkeyBytes := t.ReceiverPubKey.A.X.Bytes()
	receiverKey := string(receiverpubkeyBytes[:])
	receiver, err := o.VerifyAndGetAccount(receiverKey)
	if err != nil {
		return err
	}

	o.witnesses.SetBeforeAccounts(uint64(numTransfer), sender, receiver)
	err = o.SetMerkleProofs(true, sender, receiver, uint64(numTransfer))
	if err != nil {
		return err
	}

	senderAfter, receiverAfter, err := VerifyAndGetUpdatedAccounts(sender, receiver, t, hFunc)
	if err != nil {
		return err
	}
	o.witnesses.SetBeforeAccounts(uint64(numTransfer), senderAfter, receiverAfter)

	err = o.SetMerkleProofs(false, senderAfter, receiverAfter, uint64(numTransfer))
	if err != nil {
		return nil
	}

	return nil

}

func (o *Operator) SetMerkleProofs(before bool, sender account.Account, receiver account.Account, numTransfer uint64) error {
	merkleRootBefore, senderInclusionProofBefore, numLeaves, err := BuildProof(o.hFunc, o.StateHash, sender.Index)
	if err != nil {
		return err
	}

	err = VerifyProof(o.hFunc, merkleRootBefore, senderInclusionProofBefore, sender.Index, numLeaves)
	if err != nil {
		return err
	}
	slog.Info("sender inclusion proof is verified")

	proof := GetMerkleProofFromBytes(senderInclusionProofBefore)
	if before {
		o.witnesses.MerkleProofsSenderBefore[numTransfer] = proof
	} else {
		o.witnesses.MerkleProofsSenderAfter[numTransfer] = proof
	}

	merkleRoot, receiverInclusionProof, numLeaves, err := BuildProof(o.hFunc, o.StateHash, receiver.Index)
	if err != nil {
		return err
	}

	err = VerifyProof(o.hFunc, merkleRoot, receiverInclusionProof, receiver.Index, numLeaves)
	if err != nil {
		return err
	}
	slog.Info("receiver inclusion proof is verified")

	proof = GetMerkleProofFromBytes(receiverInclusionProof)

	if before {
		o.witnesses.MerkleProofsReceiverBefore[numTransfer] = proof

	} else {
		o.witnesses.MerkleProofsSenderAfter[numTransfer] = proof
	}

	return nil

}

func VerifyAndGetUpdatedAccounts(
	sender account.Account,
	receiver account.Account,
	t transfer.Transfer,
	hFunc hash.Hash) (account.Account, account.Account, error) {

	if sender.Balance.Cmp(&t.Amount) == -1 {
		return account.Account{}, account.Account{}, errors.New("not enough balance")
	}

	sender.Balance = *sender.Balance.Sub(&sender.Balance, &t.Amount)
	sender.Nonce++
	receiver.Balance = *receiver.Balance.Add(&receiver.Balance, &t.Amount)

	signed, err := signature.Verify(t.Message(hFunc), sender.PubKey, t.Signature.Bytes(), hFunc)
	if err != nil {
		return account.Account{}, account.Account{}, nil
	}
	if !signed {
		return account.Account{}, account.Account{}, errors.New("signature verification failed")

	}
	return sender, receiver, nil

}

func (o *Operator) VerifyAndGetAccount(accountKey string) (account.Account, error) {
	senderIndex, ok := o.AccountMap[accountKey]
	if !ok {
		return account.Account{}, errors.New("account doesn't exist")
	}

	senderAccount := o.ReadAccount(senderIndex)

	if senderAccount.Index != senderIndex {
		return account.Account{}, errors.New("account index mismatch")
	}

	return senderAccount, nil
}

func BuildProof(hFunc hash.Hash, data []byte, index uint64) ([]byte, [][]byte, uint64, error) {
	var buf bytes.Buffer

	_, err := buf.Write(data)
	if err != nil {
		return nil, nil, 0, err
	}

	return merkletree.BuildReaderProof(&buf, hFunc, hFunc.Size(), index)
}

func VerifyProof(hFunc hash.Hash, root []byte, proof [][]byte, index uint64, numLeaves uint64) error {
	verified := merkletree.VerifyProof(hFunc, root, proof, index, numLeaves)
	if !verified {
		return errors.New("inclusion proof verification failed")
	}
	return nil
}

func GetMerkleProofFromBytes(proofBytes [][]byte) merkle.MerkleProof {
	var merkleProof merkle.MerkleProof
	for i := 0; i < len(proofBytes); i++ {
		merkleProof.Path[i] = proofBytes[i]
	}
	return merkleProof
}
