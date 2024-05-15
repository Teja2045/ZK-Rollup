package proofSystem

import (
	"ZK-Rollup/circuit"
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func Verify(assignemnt circuit.Circuit) {
	var cir circuit.Circuit
	//circuit := *assignemnt
	cir.SetMerklePaths()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cir)
	if err != nil {
		fmt.Println("here0")
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println("here")
		log.Fatal(err)
	}

	witness, err := frontend.NewWitness(&assignemnt, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("her4")
		log.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("her5")
		log.Fatal(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("here1")
		log.Fatal(err)
	}

	groth16.Verify(proof, vk, publicWitness)
}
