package node

import (
	"ZK-Rollup/account"
	"ZK-Rollup/modules/transfer"
	"ZK-Rollup/signature"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

type SignatureAccount struct {
	PubKey  eddsa.PublicKey
	PrivKey eddsa.PrivateKey
}

var hFunc2 = mimc.NewMiMC()

func StartNodeWithRandomData(nbAccounts uint64, nbTransfers uint64) {

	accountsMap := make(map[uint64]SignatureAccount)
	accountsBytes := make([]byte, nbAccounts*uint64(account.AccountSizeInBytes))

	for i := uint64(0); i < nbAccounts; i++ {
		privKey, pubKey := signature.GenerateKeys(int64(i))
		accountsMap[i] = SignatureAccount{
			PubKey:  pubKey,
			PrivKey: privKey,
		}
		chainAccount := account.Account{
			Index:   i,
			Nonce:   0,
			Balance: fr.NewElement((i + 1) * 666), // random balance
			PubKey:  pubKey,
		}

		accoutMarshalled := chainAccount.Marshal()

		copy(accountsBytes[i*uint64(account.AccountSizeInBytes):], accoutMarshalled)
	}

	node := NewNode(int(nbAccounts), accountsBytes)

	go node.ListenForTransfers()
	go DoRandomTransfers(node, &accountsMap, nbTransfers)

	// blocking call
	select {}

}

func DoRandomTransfers(node Node, accounts *map[uint64]SignatureAccount, numTransfers uint64) {
	// make transactions from account one to account two
	account1 := (*accounts)[0]
	account2 := (*accounts)[1]

	for i := uint64(0); i < numTransfers; i++ {

		transfer := transfer.NewTransfer(12, account1.PubKey, account2.PubKey, i+1)
		transfer.SetSign(hFunc2, account1.PrivKey)

		// ok, err := transfer.VerifySignature(node.hFunc)

		node.queue.listTransfers <- transfer

	}
}
