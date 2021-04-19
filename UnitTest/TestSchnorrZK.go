package main

import (
	"familiar_address/SchnorrZK"
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
	"fmt"
	"strconv"
)

func main() {
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)
	G := BN254_FA.ECP2_generator()

	rng := core.NewRAND()
	var raw [100]byte
	for i := 0; i < 100; i++ {
		raw[i] = byte(i + 1)
	}
	rng.Seed(100, raw[:])

	var sk [32]byte
	skBig := BN254_FA.Randomnum(r, rng)
	skBig.ToBytes(sk[:])
	var pk [65]byte
	pkPoint := BN254_FA.G2mul(G, skBig)
	pkPoint.ToBytes(pk[:], true)

	var M [32]byte
	BN254_FA.Random(rng).ToBytes(M[:])

	E, S := SchnorrZK.SZKProve(rng, sk, M[:])
	ret := SchnorrZK.SZKVerify(pk, M[:], E, S)

	fmt.Printf("Schnorr ZK verify:" + strconv.FormatBool(ret))
}
