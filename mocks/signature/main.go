package main

import (
	"bufio"
	"fmt"
	"log"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

func main() {
	secret_mnemonic := "I am done"

	reader := strings.NewReader(secret_mnemonic)
	bufferedReader := bufio.NewReader(reader)

	privateKey, err := eddsa.GenerateKey(bufferedReader)
	if err != nil {
		fmt.Println("privatekey generation failed")
		log.Fatal(err)
	}

	pubKey := privateKey.PublicKey
	data := []byte{1, 2, 3}
	hFunc := mimc.NewMiMC()
	signature, err := privateKey.Sign(data, hFunc)
	if err != nil {
		fmt.Println("signature generation failed")
		log.Fatal(err)
	}
	data2 := []byte{1, 2, 3}
	signedCorrecly, err := pubKey.Verify(signature, data2, hFunc)
	if err != nil {
		fmt.Println("pubkey verification failed")
		log.Fatal(err)
	}

	fmt.Println("signature verified? :", signedCorrecly)
}
