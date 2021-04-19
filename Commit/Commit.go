package Commit

import (
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
)

func Commit(secrets [][]byte, rng *core.RAND) (C [32]byte, D [][]byte) {
	rnd := BN254_FA.Random(rng)

	D = make([][]byte, 0)
	var rndBytes [32]byte
	rnd.ToBytes(rndBytes[:])
	D = append(D, rndBytes[:])

	H := core.NewHASH256()
	H.Process_array(D[0])

	for i := 0; i < len(secrets); i++ {
		H.Process_array(secrets[i][:])
		D = append(D, secrets[i][:])
	}

	hashBytes := H.Hash()

	CBig := BN254_FA.FromBytes(hashBytes)
	CBig.ToBytes(C[:])

	return
}

func Verify(C [32]byte, D [][]byte) bool {
	H := core.NewHASH256()

	for i := 0; i < len(D); i++ {
		H.Process_array(D[i][:])
	}

	hashBytes := H.Hash()

	CComputeBig := BN254_FA.FromBytes(hashBytes)
	CBig := BN254_FA.FromBytes(C[:])

	if BN254_FA.Comp(CComputeBig, CBig) == 0 {
		return true
	} else {
		return false
	}
}
