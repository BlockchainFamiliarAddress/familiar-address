package main

import (
	"familiar_address/Commit"
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
	"fmt"
	"strconv"
)

func main() {
	var count int = 5

	rng := core.NewRAND()
	var raw [100]byte
	for i := 0; i < 100; i++ {
		raw[i] = byte(i + 1)
	}
	rng.Seed(100, raw[:])

	secrets := make([][]byte, 0)

	fmt.Println("Secrets are:")
	var tem [32]byte
	for i := 0; i < count; i++ {
		BN254_FA.Random(rng).ToBytes(tem[:])
		secrets = append(secrets, tem[:])
		printBinary(secrets[i][:])
	}

	C, D := Commit.Commit(secrets, rng)

	fmt.Println("C is: ")
	printBinary(C[:])

	fmt.Println("Verify Commit: ")
	fmt.Println(strconv.FormatBool(Commit.Verify(C, D)))
}

func printBinary(array []byte) {
	for i := 0; i < len(array); i++ {
		fmt.Printf("%02x", array[i])
	}
	fmt.Printf("\n")
}
