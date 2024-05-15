# ZK-Rollup
A simple zero knowledge rollup

## State
An array of accounts encoded in bytes
```
type Account struct {
	Index   uint64          // index in tree
	Nonce   uint64          // number of transactions from this account
	Balance fr.Element      // balance amount
	PubKey  eddsa.PublicKey // 2 parts of pubkey :- X, Y
}
```

## Transactions
#### Transfer
A simple money transfer from one account to another
```
type Transfer struct {
	Nonce          uint64
	Amount         fr.Element
	SenderPubKey   eddsa.PublicKey
	ReceiverPubKey eddsa.PublicKey
	Signature      eddsa.Signature
}
```

## Implementation Details
#### FullNode's Genesis will be initialised with an array of accounts
```
func NewNode(nbAccounts int, data []byte) Node {
	if len(data) != nbAccounts*account.AccountSizeInBytes {
		panic("invalid accounts data")
	}
	state := data
    ...
}
```

#### After initialising the state, the full node will start listening to  transactions via a channel
```
func (o *Node) ListenForTransfers() {
	for transfer := range o.queue.listTransfers {
		// process transfer transaction
        ...
	}
}
```

#### There should be 3 nodes:- 
- Execution Node (Full node): To executes the transactions
- ZkNode (Prover): To build circuit witness and create zk proof (It should be noted that building circuit witness and creating proof are separate functionalities)
- Verifier (Light node): who consumes zk proof and can determine if the new state root is valid or not
circuit witness based on Execution Node state updates


        Note: for now all these are simluated with in Node implementation
```
    for transfer := range o.queue.listTransfers {
		
        // update state + build witness
		err := o.UpdateState(transfer, 0)
		if err != nil {
			log.Fatal(err)
		}

        // Verifier + prover
		proofSystem.Verify(o.witnesses)
	}
```

#### To Run
    go run main.go

- It makes a simple simulation where the node will be initialized with N accounts (randomly generated pubKey+privKeys) and T number of transactions will be done by Account 1 to Account 2. Check the logs!


## Debugging
##### Slices in Circuits
```
type Circuit struct {
    X []frontend.Variable
}
```
Having Slice of frontend.Variable in the circuit will lead to a compilation error during circuit compilation. For example, merkle.MerkleProof contain a slice of frontend.Variable inside it.


Circuit should have bounded constraints, having a slice leads to unknown number of contraints.

To fix it, initialise the slice before compiling the circuit or use array instead of slice
```
func (circuit *Circuit) SetMerklePaths() {
	for i := 0; i < BatchSize; i++ {
		circuit.MerkleProofsReceiverAfter[i].Path = make([]frontend.Variable, Depth)
		circuit.MerkleProofsReceiverBefore[i].Path = make([]frontend.Variable, Depth)
		circuit.MerkleProofsSenderAfter[i].Path = make([]frontend.Variable, Depth)
		circuit.MerkleProofsSenderBefore[i].Path = make([]frontend.Variable, Depth)
	}
}
```

call this before compiling circuit (for prover)
```
    var cir circuit.Circuit
	
	cir.SetMerklePaths()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cir)
    // ...
```


#### private Varibles
```
    // invalid circuit
    type Circuit struct {
        x frontend.Varibale
    }

    //valid circuit
    type Circuit struct {
        X frontend.Variable
    }

    private variables are not allowed for circuits
```

#### Merkle Path

```
// depth depends on data
circuit.MerkleProofsReceiverAfter[i].Path = make([]frontend.Variable, Depth)
```

path size depends the number of segments of data (used to build merkle tree)