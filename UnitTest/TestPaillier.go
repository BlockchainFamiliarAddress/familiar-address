package main

import (
	"familiar_address/Paillier"
	"familiar_address/miracl/core/BN254_FA"
	"fmt"
	"math/big"
)

func main() {
	TestDecrypt()
	TestHomoAdd()
	TestHomoMul()
}

func TestDecrypt() {
	publicKey, privateKey := Paillier.GenerateKeyPair(2048)

	msg := BN254_FA.GenerateSafeRandomFromZn(publicKey.N)
	printBinary(msg.Bytes())

	cipherBytes, _ := publicKey.Encrypt(msg.Bytes())

	msgRecBytes, _ := privateKey.Decrypt(cipherBytes)

	printBinary(msgRecBytes)
	fmt.Println()
}

func TestHomoAdd() {
	publicKey, privateKey := Paillier.GenerateKeyPair(2048)

	msg1 := BN254_FA.GenerateSafeRandomFromZn(publicKey.N)
	msg2 := BN254_FA.GenerateSafeRandomFromZn(publicKey.N)

	sum := new(big.Int).Add(msg1, msg2)
	sum = new(big.Int).Mod(sum, publicKey.N)

	printBinary(sum.Bytes())

	cOne, _ := publicKey.Encrypt(msg1.Bytes())
	cTwo, _ := publicKey.Encrypt(msg2.Bytes())

	cSum := publicKey.HomoAdd(cOne, cTwo)

	sumRec, _ := privateKey.Decrypt(cSum)

	printBinary(sumRec)
	fmt.Println()
}

func TestHomoMul() {
	publicKey, privateKey := Paillier.GenerateKeyPair(2048)

	msg1 := BN254_FA.GenerateSafeRandomFromZn(publicKey.N)
	msg2 := BN254_FA.GenerateSafeRandomFromZn(publicKey.N)

	mul := new(big.Int).Mul(msg1, msg2)
	mul = new(big.Int).Mod(mul, publicKey.N)

	printBinary(mul.Bytes())

	cOne, _ := publicKey.Encrypt(msg1.Bytes())
	cMul := publicKey.HomoMul(cOne, msg2.Bytes())

	mulRec, _ := privateKey.Decrypt(cMul)

	printBinary(mulRec)
	fmt.Println()
}

func printBinary(array []byte) {
	for i := 0; i < len(array); i++ {
		fmt.Printf("%02x", array[i])
	}
	fmt.Printf("\n")
}
