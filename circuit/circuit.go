package circuit

import (
	"ZK-Rollup/account"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const (
	nbAccounts = 16 //number of account; 2 ^ 4 = 16
	depth      = 5  // depth of merkle proof; above 4 + 1 for leaf
	BatchSize  = 1  // nbTrasfers to batch in one proof
)

type AccountConstraints struct {
	Index   frontend.Variable
	Nonce   frontend.Variable
	Balance frontend.Variable
	PubKey  eddsa.PublicKey `gnark:"-"`
}

type TransferConstraints struct {
	Amount         frontend.Variable
	Nonce          frontend.Variable `gnark:"-"`
	SenderPubKey   eddsa.PublicKey   `gnark:"-"`
	ReceiverPubKey eddsa.PublicKey   `gnark:"-"`
	Signature      eddsa.Signature
}

// A circuit that checks if a transaction is valid or not
type Circuit struct {
	SenderAccountsBefore   [BatchSize]AccountConstraints
	ReceiverAccountsBefore [BatchSize]AccountConstraints
	SenderPubKeys          [BatchSize]eddsa.PublicKey

	SenderAccountsAfter   [BatchSize]AccountConstraints
	ReceiverAccountsAfter [BatchSize]AccountConstraints
	ReceiverPubKeys       [BatchSize]eddsa.PublicKey

	TransferTxs [BatchSize]TransferConstraints

	MerkleProofsReceiverBefore [BatchSize]merkle.MerkleProof
	MerkleProofsReceiverAfter  [BatchSize]merkle.MerkleProof
	MerkleProofsSenderBefore   [BatchSize]merkle.MerkleProof
	MerkleProofsSenderAfter    [BatchSize]merkle.MerkleProof

	LeafReceiver [BatchSize]frontend.Variable
	LeafSender   [BatchSize]frontend.Variable

	RootHashesBefore [BatchSize]frontend.Variable `gnark:",public"`
	RootHashesAfter  [BatchSize]frontend.Variable `gnark:",public"`
}

func NewCircuit() Circuit {
	return Circuit{
		SenderAccountsBefore:       [BatchSize]AccountConstraints{},
		ReceiverAccountsBefore:     [BatchSize]AccountConstraints{},
		SenderPubKeys:              [BatchSize]eddsa.PublicKey{},
		SenderAccountsAfter:        [BatchSize]AccountConstraints{},
		ReceiverAccountsAfter:      [BatchSize]AccountConstraints{},
		ReceiverPubKeys:            [BatchSize]eddsa.PublicKey{},
		TransferTxs:                [BatchSize]TransferConstraints{},
		MerkleProofsReceiverBefore: [BatchSize]merkle.MerkleProof{},
		MerkleProofsReceiverAfter:  [BatchSize]merkle.MerkleProof{},
		MerkleProofsSenderBefore:   [BatchSize]merkle.MerkleProof{},
		MerkleProofsSenderAfter:    [BatchSize]merkle.MerkleProof{},
		LeafReceiver:               [BatchSize]frontend.Variable{},
		LeafSender:                 [BatchSize]frontend.Variable{},
		RootHashesBefore:           [BatchSize]frontend.Variable{},
		RootHashesAfter:            [BatchSize]frontend.Variable{},
	}
}

func (circuit *Circuit) Define(api frontend.API) error {

	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	circuit.allocateSlicesMerkleProofs()

	for i := 0; i < BatchSize; i++ {

		// check if roothashes match
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofsReceiverBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesBefore[i], circuit.MerkleProofsSenderBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofsReceiverBefore[i].RootHash)
		api.AssertIsEqual(circuit.RootHashesAfter[i], circuit.MerkleProofsSenderAfter[i].RootHash)

		// check if the index is correct
		api.AssertIsEqual(circuit.ReceiverAccountsBefore[i].Index, circuit.LeafReceiver[i])
		api.AssertIsEqual(circuit.SenderAccountsBefore[i].Index, circuit.LeafSender[i])
		api.AssertIsEqual(circuit.ReceiverAccountsAfter[i].Index, circuit.LeafReceiver[i])
		api.AssertIsEqual(circuit.SenderAccountsAfter[i].Index, circuit.LeafSender[i])

		// check if merkle proofs are correct
		circuit.MerkleProofsReceiverBefore[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		circuit.MerkleProofsSenderBefore[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])
		circuit.MerkleProofsReceiverAfter[i].VerifyProof(api, &hFunc, circuit.LeafReceiver[i])
		circuit.MerkleProofsSenderAfter[i].VerifyProof(api, &hFunc, circuit.LeafSender[i])

		verifyAccountUpdated(api, circuit.ReceiverAccountsBefore[i], circuit.SenderAccountsBefore[i],
			circuit.ReceiverAccountsAfter[i], circuit.SenderAccountsAfter[i], circuit.TransferTxs[i].Amount)

		VerifySignature(api, circuit.TransferTxs[i], hFunc)
	}

	return nil
}

func (circuit *Circuit) allocateSlicesMerkleProofs() {

	for i := 0; i < BatchSize; i++ {
		// allocating slice for the Merkle paths
		circuit.MerkleProofsReceiverBefore[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofsReceiverAfter[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofsSenderBefore[i].Path = make([]frontend.Variable, depth)
		circuit.MerkleProofsSenderAfter[i].Path = make([]frontend.Variable, depth)
	}

}

func verifyAccountUpdated(api frontend.API,
	fromBefore, toBefore, fromAfter, toAfter AccountConstraints,
	amount frontend.Variable) {
	// check if nonce updated correctly
	nonceUpdated := api.Add(fromBefore.Nonce, 1)
	api.AssertIsEqual(nonceUpdated, fromAfter.Nonce)

	// check if sender has enough balance
	api.AssertIsLessOrEqual(amount, fromBefore.Balance)

	// check if the amount is deducted from sender
	senderAmountUpdated := api.Add(fromBefore.Balance, amount)
	api.AssertIsEqual(senderAmountUpdated, fromAfter.Balance)

	// check if the amount is added to the receiver
	receiverAmountUpdated := api.Add(toBefore.Balance, amount)
	api.AssertIsEqual(receiverAmountUpdated, toAfter.Balance)

}

func (circuit *Circuit) SetBeforeAccounts(index uint64, sender account.Account, receiver account.Account) Circuit {
	circuit.LeafReceiver[index] = sender.Index
	circuit.LeafSender[index] = receiver.Index

	circuit.SenderAccountsBefore[index].Balance = sender.Balance
	circuit.SenderAccountsBefore[index].Index = sender.Index
	circuit.SenderAccountsBefore[index].Nonce = sender.Nonce
	circuit.SenderAccountsBefore[index].PubKey.A.X = sender.PubKey.A.X
	circuit.SenderAccountsBefore[index].PubKey.A.Y = sender.PubKey.A.Y

	circuit.ReceiverAccountsBefore[index].Balance = receiver.Balance
	circuit.ReceiverAccountsBefore[index].Index = receiver.Index
	circuit.ReceiverAccountsBefore[index].Nonce = receiver.Nonce
	circuit.ReceiverAccountsBefore[index].PubKey.A.X = receiver.PubKey.A.X
	circuit.ReceiverAccountsBefore[index].PubKey.A.Y = receiver.PubKey.A.Y

	circuit.SenderPubKeys[index].A.X = sender.PubKey.A.X
	circuit.SenderPubKeys[index].A.Y = sender.PubKey.A.Y
	circuit.ReceiverPubKeys[index].A.X = sender.PubKey.A.X
	circuit.ReceiverPubKeys[index].A.Y = sender.PubKey.A.Y

	return *circuit

}

func (circuit *Circuit) SetAfterAccounts(index uint64, sender account.Account, receiver account.Account) {

	circuit.SenderAccountsAfter[index].Balance = sender.Balance
	circuit.SenderAccountsAfter[index].Index = sender.Index
	circuit.SenderAccountsAfter[index].Nonce = sender.Nonce
	circuit.SenderAccountsAfter[index].PubKey.A.X = sender.PubKey.A.X
	circuit.SenderAccountsAfter[index].PubKey.A.Y = sender.PubKey.A.Y

	circuit.ReceiverAccountsAfter[index].Balance = receiver.Balance
	circuit.ReceiverAccountsAfter[index].Index = receiver.Index
	circuit.ReceiverAccountsAfter[index].Nonce = receiver.Nonce
	circuit.ReceiverAccountsAfter[index].PubKey.A.X = receiver.PubKey.A.X
	circuit.ReceiverAccountsAfter[index].PubKey.A.Y = receiver.PubKey.A.Y

	circuit.SenderPubKeys[index].A.X = sender.PubKey.A.X
	circuit.SenderPubKeys[index].A.Y = sender.PubKey.A.Y
	circuit.ReceiverPubKeys[index].A.X = sender.PubKey.A.X
	circuit.ReceiverPubKeys[index].A.Y = sender.PubKey.A.Y

}

// verify the signature
func VerifySignature(api frontend.API, t TransferConstraints, hFunc mimc.MiMC) error {

	hFunc.Reset()
	hFunc.Write(t.Nonce, t.Amount, t.SenderPubKey.A.X, t.SenderPubKey.A.Y, t.ReceiverPubKey.A.X, t.ReceiverPubKey.A.Y)
	txHash := hFunc.Sum()

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	hFunc.Reset()

	return eddsa.Verify(curve, t.Signature, txHash, t.SenderPubKey, &hFunc)
}
