package main

import (
	"ZK-Rollup/signature"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	var one, two fr.Element
	one.SetUint64(10)
	one.SetUint64(20)

	fmt.Println("one vs two", one.Cmp(&two))
	fmt.Println("sum is", one.Add(&one, &two))
	fmt.Println("one", one)
	fmt.Println()
	fmt.Println()

	pvKey, pbKey := signature.GenerateKeys(1)
	fmt.Println("pv", pvKey)
	fmt.Println("pb", pbKey)

	pvKey2, pbKey2 := signature.GenerateKeys(1)
	fmt.Println("pv2", pvKey2)
	fmt.Println("pb2", &pbKey2.A.X, &pbKey.A.Y)
}
