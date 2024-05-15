package main

import (
	"ZK-Rollup/circuit"
	"ZK-Rollup/node"
)

func main() {
	node.StartNodeWithRandomData(circuit.NbAccounts, circuit.Depth)
}
