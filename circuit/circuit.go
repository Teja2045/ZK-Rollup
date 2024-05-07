package circuit

import (
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

func (circuit *Circuit) Define(api frontend.API) error {

	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

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
	}
	return nil
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

// verify the signature
func (circuit *Circuit) VerifySignature(api frontend.API, t TransferConstraints, hFunc mimc.MiMC) error {

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
