package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func main() {
	hFunc := mimc.NewMiMC()

	data := "12"
	data2 := "13"
	data3 := "14"

	root := make([]byte, hFunc.Size()*3)

	hFunc.Reset()
	hFunc.Write([]byte(data))
	hash1 := hFunc.Sum(nil)
	copy(root[:hFunc.Size()], hash1)

	hFunc.Reset()
	hFunc.Write([]byte(data2))
	hash2 := hFunc.Sum(nil)
	copy(root[hFunc.Size():], hash2)

	hFunc.Reset()
	hFunc.Write([]byte(data3))
	hash3 := hFunc.Sum(nil)
	copy(root[2*hFunc.Size():], hash3)

	fmt.Println(hash1)
	fmt.Println(hash2)
	fmt.Println(hash3)
	fmt.Println(root)

	var buf bytes.Buffer
	_, err := buf.Write(root)
	if err != nil {
		log.Fatal(err)
	}

	// The idea is the buildProof will take SEGMENT_SIZE and INDEX as inputs
	// given the SEGMENT_SIZE, it will divide the data of length DATA_SIZE in chunks,
	// with each chunk of size SEGMENT_SIZE
	// NUMBER_OF_SEGMENTS = DATA_SIZE / SEGMENT_SIZE
	// INDEX refers to the chunk index for which the inclusion proof is generated
	merkleRoot, proofInclusion, numLeaves, err := merkletree.BuildReaderProof(&buf, hFunc, hFunc.Size()/2, 4)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(merkleRoot)
	verified := merkletree.VerifyProof(hFunc, merkleRoot, proofInclusion, 4, numLeaves)
	fmt.Println(verified)

	buf.Reset()
	_, err = buf.Write(root)
	if err != nil {
		log.Fatal(err)
	}

	merkleRoot, proofInclusion, numLeaves, err = merkletree.BuildReaderProof(&buf, hFunc, hFunc.Size(), 1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(merkleRoot)
	verified = merkletree.VerifyProof(hFunc, merkleRoot, proofInclusion, 0, numLeaves)
	fmt.Println(verified)
}
