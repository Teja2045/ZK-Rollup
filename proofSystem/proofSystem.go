package proofSystem

import (
	"ZK-Rollup/circuit"
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func Verify(assignemnt circuit.Circuit, txNumber uint64) {
	start := time.Now()
	var cir circuit.Circuit
	//circuit := *assignemnt
	cir.SetMerklePaths()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cir)
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	witness, err := frontend.NewWitness(&assignemnt, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	startTime := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}
	timeInSeconds := time.Since(startTime).Seconds()
	fmt.Println("prover time:", timeInSeconds, "seconds")

	startTime = time.Now()
	groth16.Verify(proof, vk, publicWitness)
	timeInSeconds = time.Since(startTime).Seconds()
	fmt.Println("verifier time:", timeInSeconds, "seconds")
	time := time.Since(start).Seconds()
	fmt.Println("complete proof time (including setup):", time, "seconds")
	fmt.Println()
	fmt.Println("---------------- Tx-", txNumber, "Zk Proof Verified! -------------------")
}
