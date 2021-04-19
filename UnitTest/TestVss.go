package main

import (
	"familiar_address/VSS"
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
	"fmt"
	"strconv"
)

func main() {
	threshold := 6
	total := 10
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)

	rng := core.NewRAND()
	var raw [100]byte
	for i := 0; i < 100; i++ {
		raw[i] = byte(i + 1)
	}
	rng.Seed(100, raw[:])

	var secret [32]byte
	BN254_FA.Randomnum(r, rng).ToBytes(secret[:])

	fmt.Printf("secret is: \n")
	printBinary(secret[:])

	fmt.Printf("ids are: \n")
	ids := make([][32]byte, total)
	for i := 0; i < total; i++ {
		BN254_FA.Randomnum(r, rng).ToBytes(ids[i][:])
		printBinary(ids[i][:])
	}

	error, _, polyPoints, shares := VSS.Vss(secret, ids, rng, threshold, total)

	if error == -1 {
		fmt.Printf("generate vss fail!\n")
	} else {
		fmt.Printf("share verify result: \n")
		for i := 0; i < total; i++ {
			fmt.Printf(strconv.Itoa(i) + "-th share:" + strconv.FormatBool(VSS.Verify(shares[i], ids[i], polyPoints)) + "\n")
		}
	}

	fmt.Printf("combine share result: \n")
	_, secret1 := VSS.Combine(shares, ids)
	printBinary(secret1[:])
	_, secret2 := VSS.Combine(shares[:threshold], ids[:threshold])
	printBinary(secret2[:])
	_, secret3 := VSS.Combine(shares[:threshold+1], ids[:threshold+1])
	printBinary(secret3[:])
	_, secret4 := VSS.Combine(shares[:threshold-1], ids[:threshold-1])
	printBinary(secret4[:])

}

func printBinary(array []byte) {
	for i := 0; i < len(array); i++ {
		fmt.Printf("%02x", array[i])
	}
	fmt.Printf("\n")
}
