package SchnorrZK

import (
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
)

func SZKProve(rng *core.RAND, sk [32]byte, M []byte) (E [32]byte, S [32]byte) {
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)
	G := BN254_FA.ECP2_generator()

	rnd := BN254_FA.Randomnum(r, rng)
	var rndPointBytes [65]byte
	BN254_FA.G2mul(G, rnd).ToBytes(rndPointBytes[:], true)

	H := core.NewHASH256()
	H.Process_array(M)
	H.Process_array(rndPointBytes[:])
	hashBytes := H.Hash()

	e := BN254_FA.FromBytes(hashBytes)
	e.Mod(r)
	s := BN254_FA.FromBytes(sk[:])
	s = BN254_FA.Modmuladd(e, s, rnd, r)

	e.ToBytes(E[:])
	s.ToBytes(S[:])

	return
}

func SZKVerify(pk [65]byte, M []byte, E [32]byte, S [32]byte) bool {
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)
	G := BN254_FA.ECP2_generator()

	s := BN254_FA.FromBytes(S[:])
	e := BN254_FA.FromBytes(E[:])
	pkPoint := BN254_FA.ECP2_fromBytes(pk[:])

	sPoint := BN254_FA.G2mul(G, s)
	minusE := BN254_FA.Modneg(e, r)

	minusEPkPoint := BN254_FA.G2mul(pkPoint, minusE)
	minusEPkPoint.Add(sPoint)
	var epksPointBytes [65]byte
	minusEPkPoint.ToBytes(epksPointBytes[:], true)

	H := core.NewHASH256()
	H.Process_array(M)
	H.Process_array(epksPointBytes[:])
	hashBytes := H.Hash()

	eCompute := BN254_FA.FromBytes(hashBytes)
	eCompute.Mod(r)

	if BN254_FA.Comp(eCompute, e) == 0 {
		return true
	} else {
		return false
	}
}
