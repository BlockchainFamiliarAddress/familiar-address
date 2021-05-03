package Paillier

import (
	"familiar_address/miracl/core/BN254_FA"
	"math/big"
)

type PublicKey struct {
	Length int
	N      *big.Int // n = p*q, where p and q are prime, the length of N is Length
	G      *big.Int // in practical, G = N + 1
	N2     *big.Int // N2 = N * N
}

type PrivateKey struct {
	Length int
	PublicKey
	L *big.Int // (p-1)*(q-1)
	U *big.Int // L^-1 mod N
}

func GenerateKeyPair(length int) (pk *PublicKey, sk *PrivateKey) {
	one := big.NewInt(1)

	p := BN254_FA.GenerateSafeRandomPrime(length / 2)
	q := BN254_FA.GenerateSafeRandomPrime(length / 2)

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, one)

	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)

	l := new(big.Int).Mul(pMinus1, qMinus1)
	u := new(big.Int).ModInverse(l, n)

	publicKey := &PublicKey{Length: length, N: n, G: g, N2: n2}
	privateKey := &PrivateKey{Length: length, PublicKey: *publicKey, L: l, U: u}

	return publicKey, privateKey
}

func (publicKey *PublicKey) Encrypt(msgInN []byte) (retCipher []byte, error int) {
	var cipherBytes = make([]byte, publicKey.Length*2/8)

	var msgBytes = make([]byte, publicKey.Length/8)
	copy(msgBytes[publicKey.Length/8-len(msgInN):], msgInN)
	msgBig := new(big.Int).SetBytes(msgBytes)

	if msgBig.Cmp(publicKey.N) > 0 {
		return cipherBytes, -1
	}

	rndStar := BN254_FA.GenerateSafeRandomFromZnStar(publicKey.N)

	// G^m mod N2
	Gm := new(big.Int).Exp(publicKey.G, msgBig, publicKey.N2)
	// R^N mod N2
	RN := new(big.Int).Exp(rndStar, publicKey.N, publicKey.N2)
	// G^m * R^n
	GmRN := new(big.Int).Mul(Gm, RN)
	// G^m * R^n mod N2
	cipher := new(big.Int).Mod(GmRN, publicKey.N2)

	copy(cipherBytes[publicKey.Length*2/8-len(cipher.Bytes()):], cipher.Bytes())
	return cipherBytes, 1
}

func (privateKey *PrivateKey) Decrypt(cipher []byte) (retMsg []byte, error int) {
	one := big.NewInt(1)

	var msgBytes = make([]byte, privateKey.Length/8)
	cipherBig := new(big.Int).SetBytes(cipher)

	if cipherBig.Cmp(privateKey.N2) > 0 {
		return msgBytes, -1
	}

	// c^L mod N2
	cL := new(big.Int).Exp(cipherBig, privateKey.L, privateKey.N2)
	// c^L - 1
	cLMinus1 := new(big.Int).Sub(cL, one)
	// (c^L - 1) / N
	cLMinus1DivN := new(big.Int).Div(cLMinus1, privateKey.N)
	// (c^L - 1) / N * U
	cLMinus1DivNMulU := new(big.Int).Mul(cLMinus1DivN, privateKey.U)
	// (c^L - 1) / N * U mod N
	mBig := new(big.Int).Mod(cLMinus1DivNMulU, privateKey.N)

	copy(msgBytes[privateKey.Length/8-len(mBig.Bytes()):], mBig.Bytes())
	return msgBytes, 1
}

func (publicKey *PublicKey) HomoAdd(c1, c2 []byte) (cipher []byte) {
	c1Big := new(big.Int).SetBytes(c1)
	c2Big := new(big.Int).SetBytes(c2)
	// c1 * c2
	c1c2 := new(big.Int).Mul(c1Big, c2Big)
	// c1 * c2 mod N2
	newCipher := new(big.Int).Mod(c1c2, publicKey.N2)

	var cipherBytes = make([]byte, publicKey.Length*2/8)
	copy(cipherBytes[publicKey.Length*2/8-len(newCipher.Bytes()):], newCipher.Bytes())
	return cipherBytes
}

func (publicKey *PublicKey) HomoMul(c, k []byte) (cipher []byte) {
	cBig := new(big.Int).SetBytes(c)
	kBig := new(big.Int).SetBytes(k)

	// cipher^k mod N2
	newCipher := new(big.Int).Exp(cBig, kBig, publicKey.N2)

	var cipherBytes = make([]byte, publicKey.Length*2/8)
	copy(cipherBytes[publicKey.Length*2/8-len(newCipher.Bytes()):], newCipher.Bytes())
	return cipherBytes
}
