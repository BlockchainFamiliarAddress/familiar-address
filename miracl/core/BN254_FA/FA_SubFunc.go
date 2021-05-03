package BN254_FA

import "familiar_address/miracl/core"

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
