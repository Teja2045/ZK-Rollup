package node

import (
	"ZK-Rollup/account"
	"ZK-Rollup/circuit"
	"ZK-Rollup/modules/transfer"
	"ZK-Rollup/proofSystem"
	"time"

	"ZK-Rollup/signature"
	"bytes"
	"errors"
	"fmt"
	"hash"
	"log"
	"log/slog"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
)

var hFunc = mimc.NewMiMC()

var MaxTxBuffer = 10

type Queue struct {
	txChannel chan transfer.Transfer
}

func NewQueue(circuitBatchSize int) Queue {
	resChan := make(chan transfer.Transfer, circuitBatchSize)
	return Queue{
		txChannel: resChan,
	}
}

type Node struct {
	TxCount    uint64
	State      []byte            // list of account bytes appended
	StateHash  []byte            // hash of account bytes appended
	AccountMap map[string]uint64 // pubkey to index map
	nbAccounts int               // number of accounts
	hFunc      hash.Hash         // hash function used
	queue      Queue             // channel which recieves transfer request
	batch      int               // tx count?
	witnesses  circuit.Circuit   // circuit
}

func NewNode(nbAccounts int, data []byte) Node {
	if len(data) != nbAccounts*account.AccountSizeInBytes {
		panic("invalid accounts data")
	}
	state := data
	hashState := make([]byte, nbAccounts*hFunc.Size())
	accountsMap := make(map[string]uint64)

	for i := 0; i < nbAccounts; i++ {
		hFunc.Reset()
		accountBytes := state[account.AccountSizeInBytes*i : account.AccountSizeInBytes*(i+1)]
		hFunc.Write(accountBytes)
		accountHash := hFunc.Sum(nil)
		copy(hashState[hFunc.Size()*i:hFunc.Size()*(i+1)], accountHash)
		var acc account.Account
		account.UnMarshal(&acc, accountBytes)
		keyBytes := acc.PubKey.A.X.Bytes()
		accountsMap[string(keyBytes[:])] = uint64(i)

	}

	queue := NewQueue(MaxTxBuffer)
	circuit := circuit.NewCircuit()

	return Node{
		TxCount:    0,
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

func (o *Node) ListenForTransfers() {
	for transfer := range o.queue.txChannel {
		startTime := time.Now()
		slog.Info("recieved transaction!")

		// TODO: check tx before updating state
		// update state
		err := o.UpdateState(transfer, 0)
		if err != nil {
			// TODO: handle gracefully
			log.Fatal(err)
		}

		o.TxCount++

		// TODO: indendent Prover node and Verifier Node
		// generate Zk-proof and Verify the proof
		proofSystem.Verify(o.witnesses, o.TxCount)
		timeInSeconds := time.Since(startTime).Seconds()
		slog.Info(fmt.Sprintln("Time taken for complete transaction life cycle:", timeInSeconds, "seconds!"))
		fmt.Println()
		fmt.Println()
	}
}

// Read Account from state (byte data)
func (o *Node) ReadAccount(i uint64) account.Account {
	accountBytes := o.State[account.AccountSizeInBytes*int(i) : (int(i)+1)*account.AccountSizeInBytes]
	var acc account.Account
	if err := account.UnMarshal(&acc, accountBytes); err != nil {
		log.Fatal(err)
	}
	return acc
}

// update state + build witness of zk circuit
func (o *Node) UpdateState(t transfer.Transfer, numTransfer int) error {

	slog.Info("updating state...")
	senderpubkeyBytes := t.SenderPubKey.A.X.Bytes()
	senderKey := string(senderpubkeyBytes[:])

	sender, err := o.VerifyAndGetAccount(senderKey)
	if err != nil {
		slog.Error("sender not verified")
		return err
	}

	receiverpubkeyBytes := t.ReceiverPubKey.A.X.Bytes()
	receiverKey := string(receiverpubkeyBytes[:])

	receiver, err := o.VerifyAndGetAccount(receiverKey)
	if err != nil {
		slog.Error("receiver not verified")
		return err
	}

	// set before accounts  & pubkeys & leaf accounts
	o.witnesses.SetBeforeAccounts(uint64(numTransfer), sender, receiver)

	// set before accounts before merkle proofs & before merkle root
	err = o.SetMerkleProofs(true, sender, receiver, uint64(numTransfer))
	if err != nil {
		slog.Error("unable to set merkle proofs")
		return err
	}

	senderAfter, receiverAfter, err := VerifyAndGetUpdatedAccounts(sender, receiver, t, hFunc)
	if err != nil {
		slog.Error("unable to get updated accounts")
		return err
	}

	// update state
	o.UpdateAccounts(senderAfter, receiverAfter)

	// set after accounts
	o.witnesses.SetAfterAccounts(uint64(numTransfer), senderAfter, receiverAfter)

	// set after merkle proofs & after merkle roots
	err = o.SetMerkleProofs(false, senderAfter, receiverAfter, uint64(numTransfer))
	if err != nil {
		return err
	}

	// set transfer contraints
	o.SetTxns(uint64(numTransfer), t)

	slog.Info(fmt.Sprintf("sender account-%d balance before tx: %s", sender.Index, sender.Balance.String()))
	slog.Info(fmt.Sprintf("sender account-%d balance after tx: %s", sender.Index, senderAfter.Balance.String()))
	slog.Info(fmt.Sprintf("receiver account-%d balance before tx: %s", receiver.Index, receiver.Balance.String()))
	slog.Info(fmt.Sprintf("receiver account-%d balance after tx: %s", receiver.Index, receiverAfter.Balance.String()))

	slog.Info("state updated successfully!!")

	fmt.Println()
	return nil

}

func (o *Node) SetTxns(numTransfer uint64, t transfer.Transfer) {
	var frNonce fr.Element

	// Convert uint64 to bytes
	frNonce.SetUint64(t.Nonce)
	o.witnesses.TransferTxs[numTransfer].Amount = t.Amount
	o.witnesses.TransferTxs[numTransfer].Nonce = frNonce
	o.witnesses.TransferTxs[numTransfer].SenderPubKey.A.X = t.SenderPubKey.A.X
	o.witnesses.TransferTxs[numTransfer].SenderPubKey.A.Y = t.SenderPubKey.A.Y
	o.witnesses.TransferTxs[numTransfer].ReceiverPubKey.A.X = t.ReceiverPubKey.A.X
	o.witnesses.TransferTxs[numTransfer].ReceiverPubKey.A.Y = t.ReceiverPubKey.A.Y
	o.witnesses.TransferTxs[numTransfer].Signature.R.X = t.Signature.R.X
	o.witnesses.TransferTxs[numTransfer].Signature.R.Y = t.Signature.R.Y
	o.witnesses.TransferTxs[numTransfer].Signature.S = t.Signature.S[:]
}

func (o *Node) UpdateAccounts(sender account.Account, receiver account.Account) {
	o.hFunc.Reset()
	senderBytes := sender.Marshal()
	o.hFunc.Write(senderBytes)
	hash := o.hFunc.Sum(nil)
	copy(o.StateHash[sender.Index*uint64(o.hFunc.Size()):], hash)
	copy(o.State[sender.Index*uint64(account.AccountSizeInBytes):], senderBytes)

	o.hFunc.Reset()
	receiverBytes := receiver.Marshal()
	o.hFunc.Write(receiverBytes)
	hash = o.hFunc.Sum(nil)
	copy(o.StateHash[receiver.Index*uint64(o.hFunc.Size()):], hash)
	copy(o.State[receiver.Index*uint64(account.AccountSizeInBytes):], receiverBytes)
}

func (o *Node) SetMerkleProofs(before bool, sender account.Account, receiver account.Account, numTransfer uint64) error {
	merkleRootBefore, senderInclusionProof, numLeaves, err := BuildProof(o.hFunc, o.StateHash, sender.Index)
	if err != nil {
		return err
	}

	err = VerifyProof(o.hFunc, merkleRootBefore, senderInclusionProof, sender.Index, numLeaves)
	if err != nil {
		return err
	}

	slog.Info("sender inclusion proof is verified")

	proof := GetMerkleProofFromBytes(merkleRootBefore, senderInclusionProof)
	if before {
		o.witnesses.MerkleProofsSenderBefore[numTransfer] = proof
	} else {
		o.witnesses.MerkleProofsSenderAfter[numTransfer] = proof
	}

	merkleRoot, receiverInclusionProof, numLeaves, err := BuildProof(o.hFunc, o.StateHash, receiver.Index)
	if err != nil {
		return err
	}

	if before {
		o.witnesses.RootHashesBefore[numTransfer] = merkleRoot
	} else {
		o.witnesses.RootHashesAfter[numTransfer] = merkleRoot
	}

	err = VerifyProof(o.hFunc, merkleRoot, receiverInclusionProof, receiver.Index, numLeaves)
	if err != nil {
		return err
	}
	slog.Info("receiver inclusion proof is verified")

	proof = GetMerkleProofFromBytes(merkleRoot, receiverInclusionProof)

	if before {
		o.witnesses.MerkleProofsReceiverBefore[numTransfer] = proof

	} else {
		o.witnesses.MerkleProofsReceiverAfter[numTransfer] = proof
	}

	return nil

}

func BuildProof(hFunc hash.Hash, data []byte, index uint64) ([]byte, [][]byte, uint64, error) {
	var buf bytes.Buffer

	_, err := buf.Write(data)
	if err != nil {
		return nil, nil, 0, err
	}

	return merkletree.BuildReaderProof(&buf, hFunc, hFunc.Size(), index)
}

func GetMerkleProofFromBytes(rootBytes []byte, proofBytes [][]byte) merkle.MerkleProof {
	var merkleProof merkle.MerkleProof
	merkleProof.RootHash = rootBytes
	merkleProof.Path = make([]frontend.Variable, len(proofBytes))
	for i := 0; i < len(proofBytes); i++ {
		merkleProof.Path[i] = proofBytes[i]
	}
	return merkleProof
}

func VerifyProof(hFunc hash.Hash, root []byte, proof [][]byte, index uint64, numLeaves uint64) error {
	verified := merkletree.VerifyProof(hFunc, root, proof, index, numLeaves)
	if !verified {
		return errors.New("inclusion proof verification failed")
	}
	return nil
}

func (o *Node) VerifyAndGetAccount(accountKey string) (account.Account, error) {
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

func VerifyAndGetUpdatedAccounts(
	sender account.Account,
	receiver account.Account,
	t transfer.Transfer,
	hFunc hash.Hash) (account.Account, account.Account, error) {

	if sender.Balance.Cmp(&t.Amount) == -1 {
		return account.Account{}, account.Account{}, errors.New("not enough balance")
	}

	sender.Balance = *sender.Balance.Sub(&sender.Balance, &t.Amount)
	sender.Nonce = sender.Nonce + 1
	receiver.Balance = *receiver.Balance.Add(&receiver.Balance, &t.Amount)

	signed, err := signature.Verify(t.Message(hFunc), sender.PubKey, t.Signature.Bytes(), hFunc)
	if err != nil {
		return account.Account{}, account.Account{}, err
	}
	if !signed {
		return account.Account{}, account.Account{}, errors.New("signature verification failed")

	}

	return sender, receiver, nil

}
