package BN254_FA

import (
	crand "crypto/rand"
	"familiar_address/miracl/core"
	"fmt"
	"math/big"
)

/* generate key pair, private key S, public key W */
func KeyPairGenerateFA(rng *core.RAND, S []byte, W []byte) int {
	r := NewBIGints(CURVE_Order)
	G := ECP2_generator()
	if G.Is_infinity() {
		return BLS_FAIL
	}
	s := Randomnum(r, rng)
	s.ToBytes(S)
	// SkToPk
	G = G2mul(G, s)
	G.ToBytes(W, true)
	return BLS_OK
}

func GenerateSafeRandomPrime(length int) (prime *big.Int) {
	rndInt, err := crand.Prime(crand.Reader, length)
	if err != nil {
		fmt.Println("ERROR when generate Safe Random Prime!")
		return nil
	}

	return rndInt
}

func GenerateSafeRandomFromZn(n *big.Int) (rndZn *big.Int) {
	rndNumZn, err := crand.Int(crand.Reader, n)
	if err != nil {
		fmt.Println("ERROR when generate Safe Random!")
		return nil
	}

	return rndNumZn
}

func GenerateSafeRandomFromZnStar(n *big.Int) (rndZnStar *big.Int) {
	gcdNum := big.NewInt(0)
	one := big.NewInt(1)

	for {
		rndNumZnStar, err := crand.Int(crand.Reader, n)
		if err != nil {
			fmt.Println("ERROR when generate Safe Random!")
			return nil
		}

		if rndNumZnStar.Cmp(n) < 0 && rndNumZnStar.Cmp(one) >= 0 && gcdNum.GCD(nil, nil, rndNumZnStar, n).Cmp(one) == 0 {
			return rndNumZnStar
		}
	}

	return nil
}

func GenerateSafeRandomFromZnBytes(nBytes []byte) (rndZnBytes []byte) {
	n := new(big.Int).SetBytes(nBytes)

	rndNumZn, err := crand.Int(crand.Reader, n)
	if err != nil {
		fmt.Println("ERROR when generate Safe Random!")
		return nil
	}

	var ret = make([]byte, len(nBytes))
	copy(ret[len(nBytes)-len(rndNumZn.Bytes()):], rndNumZn.Bytes())

	return ret
}

func GenerateSafeRandomFromZnStarBytes(nBytes []byte) (rndZnStarBytes []byte) {
	n := new(big.Int).SetBytes(nBytes)

	gcdNum := big.NewInt(0)
	one := big.NewInt(1)

	var rndNumZnStar *big.Int
	var ret = make([]byte, len(nBytes))
	var err error

	for {
		rndNumZnStar, err = crand.Int(crand.Reader, n)
		if err != nil {
			fmt.Println("ERROR when generate Safe Random!")
			return nil
		}

		if rndNumZnStar.Cmp(n) < 0 && rndNumZnStar.Cmp(one) >= 0 && gcdNum.GCD(nil, nil, rndNumZnStar, n).Cmp(one) == 0 {
			break
		}
	}

	copy(ret[len(nBytes)-len(rndNumZnStar.Bytes()):], rndNumZnStar.Bytes())

	return ret
}
