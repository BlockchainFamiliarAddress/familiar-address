package main

import (
	"familiar_address/Commit"
	"familiar_address/Paillier"
	"familiar_address/SchnorrZK"
	"familiar_address/VSS"
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
	"fmt"
	"math/big"
	"strconv"
)

// variables

var r *BN254_FA.BIG = BN254_FA.NewBIGints(BN254_FA.CURVE_Order)
var G1 *BN254_FA.ECP = BN254_FA.ECP_generator()
var G2 *BN254_FA.ECP2 = BN254_FA.ECP2_generator()

var N int = 5 // number of all PKG
var T int = 3 // threshold
var K int = 4 // number of involved PKG to issue user familiar key

// variables in protocol "master_key_share_generate"

var seeds = make([][100]byte, N)
var rngs = make([]*core.RAND, N)

var ids = make([][32]byte, N)

var Sks = make([][32]byte, N)
var Pks = make([][65]byte, N)

var PaillierKeyLength = 2048
var PaillierPks = make([]*Paillier.PublicKey, N)
var PaillierSks = make([]*Paillier.PrivateKey, N)

var polyss = make([][][32]byte, N)
var polyPointss = make([][][65]byte, N)
var sharess = make([][][32]byte, N)

var msgSks = make([][32]byte, N)
var ESks = make([][32]byte, N)
var SSks = make([][32]byte, N)

var CSks = make([][32]byte, N)
var DSks = make([][][]byte, N)

var MSks = make([][32]byte, N)
var MPk [65]byte

// variables in protocol "user_familiar_key_generate"

var userSeed [100]byte
var userRng *core.RAND

var ID []byte
var blind [32]byte
var blindQ [65]byte

var as = make([][32]byte, K)
var As = make([][65]byte, K)

var msgAs = make([][32]byte, K)
var EAs = make([][32]byte, K)
var SAs = make([][32]byte, K)

var CAs = make([][32]byte, K)
var DAs = make([][][]byte, K)

var lagPolys = make([][32]byte, K)

var bs = make([][32]byte, K)

var aCiphers = make([][]byte, 0) // length K, use append to add

var NSubN2Bytes []byte // paillier.N - pair.r ^ 2

var betaHatss [][][]byte // -beta, but absolute value
var betass [][][]byte
var alphaCipherss [][][]byte
var alphass [][][]byte
var cs [][]byte
var csSign = make([]int, K) // if -1, then cs[i] is neg

func master_key_share_generate() {

	// every PKG generates his own seed (saved in seeds, 100byte) used in PRNG
	// every PKG generates his own PRNG (saved in rngs)
	fmt.Println("\nevery PKG generates his own seed (saved in seeds, 100byte) used in PRNG")
	fmt.Println("every PKG generates his own PRNG (saved in rngs)")
	for i := 0; i < N; i++ {
		for j := 0; j < 100; j++ {
			seeds[i][j] = byte(i * j)
		}

		rngs[i] = core.NewRAND()
		rngs[i].Seed(100, seeds[i][:])
	}

	// every PKG generates his id (saved in ids, 32byte)
	// every PKG generates his private key (saved in Sks, 32byte) and public key (saved in Pks, 65byte, compressed)
	fmt.Println("\nevery PKG generates his id (saved in ids, 32byte)")
	fmt.Println("every PKG generates his private key (saved in Sks, 32byte) and public key (saved in Pks, 65byte, compressed)")
	for i := 0; i < N; i++ {
		BN254_FA.Randomnum(r, rngs[i]).ToBytes(ids[i][:])

		res := BN254_FA.KeyPairGenerateFA(rngs[i], Sks[i][:], Pks[i][:])
		if res != 0 {
			fmt.Printf(strconv.Itoa(i) + "-th PKG, Failed to generate keys\n")
			return
		}
		fmt.Printf(strconv.Itoa(i) + "-th PKG, Private key : 0x")
		printBinary(Sks[i][:])
		fmt.Printf(strconv.Itoa(i) + "-th PKG, Public  key : 0x")
		printBinary(Pks[i][:])
	}

	// every PKG generates his paillier key pair (PaillierPks, PaillierSks) and broadcast the public
	for i := 0; i < N; i++ {
		PaillierPks[i], PaillierSks[i] = Paillier.GenerateKeyPair(PaillierKeyLength)
	}

	// every PKG generates his vss shares (saved in sharess, 32byte) on private key, as well as
	// 		poly parameters (saved in polyss, 32byte) and
	// 		poly parameter multi generator of G1 group (saved in polyPointss, 65byte)
	fmt.Println("\nevery PKG generates his vss shares (saved in sharess, 32byte) on private key, as well as")
	fmt.Println("		poly parameters (saved in polyss, 32byte) and")
	fmt.Println("		poly parameter multi generator of G1 group (saved in polyPointss, 65byte)")
	for i := 0; i < N; i++ {
		vssError, polys, polyPoints, shares := VSS.Vss(Sks[i], ids, rngs[i], T, N)
		if vssError < 0 {
			fmt.Println(strconv.Itoa(i) + "-th PKG, Failed to Vss\n")
			return
		}
		polyss[i] = polys
		polyPointss[i] = polyPoints
		sharess[i] = shares
	}

	// every PKG generate sk's schnorr zk proof (saved in ESks, SSks, 32byte) on random num (saved in msgSks, 32byte)
	fmt.Println("\nevery PKG generate schnorr sk's zk proof (saved in ESks, SSks, 32byte) on random num (saved in msgSks, 32byte)")
	for i := 0; i < N; i++ {
		BN254_FA.Random(rngs[i]).ToBytes(msgSks[i][:])
		_, ESks[i], SSks[i] = SchnorrZK.SZKProve(rngs[i], 2, Sks[i], msgSks[i][:])
	}

	// every PKG commit (saved in CSks, 32byte, DSks) to pk, the above sk's schnorr zk proof and polyPointss
	fmt.Println("\nevery PKG commit (saved in Cs, 32byte, Ds) to pk, the above sk's schnorr zk proof and polyPointss")
	for i := 0; i < N; i++ {
		var secrets = make([][]byte, 0)
		secrets = append(secrets, Pks[i][:])
		secrets = append(secrets, ESks[i][:])
		secrets = append(secrets, SSks[i][:])
		secrets = append(secrets, msgSks[i][:])
		for j := 0; j < T; j++ {
			secrets = append(secrets, polyPointss[i][j][:])
		}

		CSks[i], DSks[i] = Commit.Commit(secrets, rngs[i])
	}

	// every PKG broadcasts the commit C
	// when all the PKG received the commit C, each PKG broadcast the commit D
	// every PKG validate the commit and validate the schnorr zk proof
	fmt.Println("\nevery PKG broadcasts the commit C")
	fmt.Println("when all the PKG received the commit C, each PKG broadcast the commit D")
	fmt.Println("\nevery PKG validate the commit and validate the schnorr zk proof")
	fmt.Println("validate commit:")
	for i := 0; i < N; i++ {
		fmt.Println(strconv.FormatBool(Commit.Verify(CSks[i], DSks[i])))
	}
	fmt.Println("\nvalidate schnorr zk proof:")
	for i := 0; i < N; i++ {
		var temE [32]byte
		var temS [32]byte
		copy(temE[:], DSks[i][2])
		copy(temS[:], DSks[i][3])
		fmt.Println(strconv.FormatBool(SchnorrZK.SZKVerify(2, Pks[i], DSks[i][4], temE, temS)))
	}

	// every PKG sends the vss share to corresponding PKG through secure channel
	// 		example: PKG i sends sharess[i][j] to PKG j
	fmt.Println("\nevery PKG sends the vss share to corresponding PKG through secure channel")
	fmt.Println("		example: PKG i sends sharess[i][j] to PKG j")
	fmt.Println("\nevery PKG validate the received vss share")
	// every PKG validate the received vss share
	for i := 0; i < N; i++ {
		fmt.Println(strconv.Itoa(i) + "-th PKG's vss shares:")
		for j := 0; j < N; j++ {
			var temArr [][65]byte
			var tem [65]byte
			for k := 0; k < len(DSks[j][5:]); k++ {
				copy(tem[:], DSks[j][k+5])
				temArr = append(temArr, tem)
			}
			fmt.Println(strconv.FormatBool(VSS.Verify(sharess[j][i], ids[i], temArr)))
		}
	}

	// every PKG calculates the master private key share (saved in MSks, 32byte) and public key
	// 		example: PKG i calculate the sum of sharess[j][i] j in (0, N-1) as MSk
	fmt.Println("\nevery PKG calculates the master private key share (saved in MSks, 32byte) and public key (saved in MPk, 65byte)")
	fmt.Println("example: PKG i calculate the sum of sharess[j][i] j in (1, N) as MSk")
	MPkPoint := BN254_FA.ECP2_fromBytes(DSks[0][1])
	for i := 0; i < N; i++ {
		fmt.Println(strconv.Itoa(i) + "-th PKG's MSk:")
		MSk := BN254_FA.NewBIG()
		for j := 0; j < N; j++ {
			temBig := BN254_FA.FromBytes(sharess[j][i][:])
			MSk = BN254_FA.Modadd(MSk, temBig, r)
		}
		MSk.ToBytes(MSks[i][:])
		printBinary(MSks[i][:])

		temPoint := BN254_FA.ECP2_fromBytes(DSks[i][1])
		if i > 0 {
			MPkPoint.Add(temPoint)
		}
	}

	fmt.Println("Master public key, MPk:")
	MPkPoint.ToBytes(MPk[:], true)
	printBinary(MPk[:])

	// test MSks and MPk valid
	fmt.Println("\nTest MSks and MPk valid")
	_, mskRec := VSS.Combine(MSks, ids)
	mskRecBig := BN254_FA.FromBytes(mskRec[:])
	mpkPoingRec := BN254_FA.G2mul(G2, mskRecBig)

	fmt.Println(strconv.FormatBool(mpkPoingRec.Equals(MPkPoint)))
}

func user_familiar_key_generate() {
	// calculate NSubN2Bytes (saved in NSubN2Bytes, paillier.N - pair.r ^ 2), used for c = MtA(a, b)
	{
		pNSalt := new(big.Int).Lsh(big.NewInt(1), uint(PaillierPks[0].Length-3))
		var rBytes [32]byte
		r.ToBytes(rBytes[:])
		rBigInt := new(big.Int).SetBytes(rBytes[:])
		r2BigInt := new(big.Int).Mul(rBigInt, rBigInt)
		NSubN2 := new(big.Int).Sub(pNSalt, r2BigInt)

		NSubN2Bytes = NSubN2.Bytes()
	}

	// user generates his own seed (saved in userSeed, 100byte) used in PRNG
	// user generates his own PRNG (saved in userRng)
	for j := 0; j < 100; j++ {
		userSeed[j] = byte(j * j)
	}

	userRng = core.NewRAND()
	userRng.Seed(100, userSeed[:])

	// user set familiar ID (saved in ID)
	// user calculate blind key (saved in blindQ) as blind rnd (saved in blind) multiple G1
	ID = []byte("xichan@163.com")
	blindBig := BN254_FA.Randomnum(r, userRng)
	blindBig.ToBytes(blind[:])
	blindQPoint := BN254_FA.G1mul(G1, blindBig)
	blindQPoint.ToBytes(blindQ[:], true)

	// user sends (ID, blindQ) to PKG i where i in (1, K) and K >= T

	// every PKG select random number a (saved in as, 32byte), and
	// 		calculate A (saved in As, 65byte) by multiplying a and blindQ
	{
		var rBytes [32]byte
		r.ToBytes(rBytes[:])

		for i := 0; i < K; i++ {
			copy(as[i][:], BN254_FA.GenerateSafeRandomFromZnStarBytes(rBytes[:]))
			// BN254_FA.Randomnum(r, rngs[i]).ToBytes(as[i][:]) // check if znstar
			aBig := BN254_FA.FromBytes(as[i][:])
			BN254_FA.G1mul(blindQPoint, aBig).ToBytes(As[i][:], true)
		}
	}

	// every PKG generate a's schnorr zk proof (saved in EAs, SAs, 32byte) on random num (saved in msgAs, 32byte)
	fmt.Println("\nevery PKG generate a's schnorr zk proof (saved in EAs, SAs, 32byte) on random num (saved in msgAs, 32byte)")
	for i := 0; i < K; i++ {
		BN254_FA.Random(rngs[i]).ToBytes(msgAs[i][:])

		aBig := BN254_FA.FromBytes(as[i][:])
		var aBlindBytes [32]byte
		BN254_FA.Modmul(aBig, blindBig, r).ToBytes(aBlindBytes[:])

		_, EAs[i], SAs[i] = SchnorrZK.SZKProve(rngs[i], 1, aBlindBytes, msgAs[i][:])
	}

	// every PKG commit (saved in CAs, 32byte, DAs) to A and the above a's schnorr zk proof
	fmt.Println("\nevery PKG commit (saved in CAs, 32byte, DAs) to A and the above a's schnorr zk proof")
	for i := 0; i < K; i++ {
		var secrets = make([][]byte, 0)
		secrets = append(secrets, As[i][:])
		secrets = append(secrets, EAs[i][:])
		secrets = append(secrets, SAs[i][:])
		secrets = append(secrets, msgAs[i][:])

		CAs[i], DAs[i] = Commit.Commit(secrets, rngs[i])
	}

	// every PKG broadcasts the commit C
	// when all the PKG received the commit C, each PKG broadcast the commit D
	// every PKG validate the commit and validate the a's schnorr zk proof
	fmt.Println("\nevery PKG broadcasts the commit C")
	fmt.Println("when all the PKG received the commit C, each PKG broadcast the commit D")
	fmt.Println("\nevery PKG validate the commit and validate the a's schnorr zk proof")
	fmt.Println("validate commit:")
	for i := 0; i < K; i++ {
		fmt.Println(strconv.FormatBool(Commit.Verify(CAs[i], DAs[i])))
	}
	fmt.Println("\nvalidate a's schnorr zk proof:")
	for i := 0; i < K; i++ {
		var temE [32]byte
		var temS [32]byte
		copy(temE[:], DAs[i][2])
		copy(temS[:], DAs[i][3])
		fmt.Println(strconv.FormatBool(SchnorrZK.SZKVerify(1, As[i], DAs[i][4], temE, temS)))
	}

	// every PKG calculates LagrangPolynomial (saved in lagPolys, 32byte)
	for i := 0; i < K; i++ {
		var temIds [][32]byte
		for j := 0; j < K; j++ {
			if j != i {
				temIds = append(temIds, ids[j])
			}
		}

		lagPolyBytes := VSS.GetLagrangePolynomial(temIds, ids[i])
		lagPolys[i] = lagPolyBytes
	}

	// every PKG calculates b_i = MSk_i*lagPoly + h(ID)/K mod r (saved in bs, 32byte)
	KInvBig := BN254_FA.NewBIG()
	KInvBig.SetInt(K)
	KInvBig.Invmodp(r)

	for i := 0; i < K; i++ {
		H := core.NewHASH256()
		H.Process_array(ID)
		HIDBytes := H.Hash()
		HIDBig := BN254_FA.FromBytes(HIDBytes)

		mSkBig := BN254_FA.FromBytes(MSks[i][:])
		lagPolyBig := BN254_FA.FromBytes(lagPolys[i][:])

		mSkBig = BN254_FA.Modmul(mSkBig, lagPolyBig, r)

		BN254_FA.Modmuladd(HIDBig, KInvBig, mSkBig, r).ToBytes(bs[i][:])
	}

	// every PKG i paillier encrypts his a_i to get aCipher_i (saved in aCiphers) and broadcast aCipher
	for i := 0; i < K; i++ {
		cipherBytes, _ := PaillierPks[i].Encrypt(as[i][:])
		aCiphers = append(aCiphers, cipherBytes)
	}

	// every PKG i randomly selects betaHat_ij (saved in betaHatss, from NSubN2Bytes) for j in (1, K)
	// 		and set beta_ij (saved in betass) - betaHat_ij
	{
		NSubN2 := new(big.Int).SetBytes(NSubN2Bytes)
		for i := 0; i < K; i++ {
			var temBetaHats = make([][]byte, 0)
			var temBetas = make([][]byte, 0)
			for j := 0; j < K; j++ {
				var temBetaHat *big.Int
				var temBeta *big.Int

				temBetaHat = BN254_FA.GenerateSafeRandomFromZn(NSubN2)
				temBetaHats = append(temBetaHats, temBetaHat.Bytes())

				temBeta = new(big.Int).Neg(temBetaHat)
				temBetas = append(temBetas, temBeta.Bytes())
			}
			betaHatss = append(betaHatss, temBetaHats)
			betass = append(betass, temBetas)
		}

		beta00 := new(big.Int).SetBytes(betass[0][0])
		betaHat00 := new(big.Int).SetBytes(betaHatss[0][0])

		fmt.Println("equal?")
		printBinary(beta00.Bytes())
		printBinary(betaHat00.Bytes())
	}

	// every PKG i calculates alphaCipher_ij (saved in alphaCipherss) by aCipher_j homemul b_i homeadd betaHat_ij for j in (1, K)
	// 		and sends back to PKG j
	{
		for i := 0; i < K; i++ {
			var temAlphaCiphers = make([][]byte, 0)
			for j := 0; j < K; j++ {
				cipherBetaHat, _ := PaillierPks[j].Encrypt(betaHatss[i][j])
				cMul := PaillierPks[j].HomoMul(aCiphers[j], bs[i][:])
				cSum := PaillierPks[j].HomoAdd(cipherBetaHat, cMul)

				temAlphaCiphers = append(temAlphaCiphers, cSum)
			}
			alphaCipherss = append(alphaCipherss, temAlphaCiphers)
		}
	}

	// every PKG i paillier decrypts the received alphaCipher_ji to alpha_ji (saved in alphass)
	// note: alphaCipherss[i][j] is generated by PKG i with PKG j 's aCipher, so should decrypt by PKG j
	{
		for i := 0; i < K; i++ {
			var temAlphas = make([][]byte, 0)
			for j := 0; j < K; j++ {
				temAlpha, _ := PaillierSks[i].Decrypt(alphaCipherss[j][i])
				temAlphas = append(temAlphas, temAlpha)
			}
			alphass = append(alphass, temAlphas)
		}
	}
	// every PKG i calcalulates the c_i (saved in cs)
	{
		for i := 0; i < K; i++ {
			temC := new(big.Int).SetBytes(betass[i][0])
			temC = new(big.Int).Neg(temC)
			for j := 1; j < K; j++ {
				temC = new(big.Int).Sub(temC, new(big.Int).SetBytes(betass[i][j]))
			}
			for j := 0; j < K; j++ {
				temC = new(big.Int).Add(temC, new(big.Int).SetBytes(alphass[i][j]))
			}
			cs = append(cs, temC.Bytes())
			csSign[i] = temC.Sign()
		}
	}
}

func verify_cs() {
	fmt.Println("Verify cs:")
	{
		alpha01 := new(big.Int).SetBytes(alphass[0][1])
		beta10 := new(big.Int).SetBytes(betass[1][0])
		abSum := new(big.Int).Sub(alpha01, beta10)

		a0 := new(big.Int).SetBytes(as[0][:])
		b1 := new(big.Int).SetBytes(bs[1][:])
		abSumCal := new(big.Int).Mul(a0, b1)

		fmt.Println("a0 * b1:")
		printBinary(abSum.Bytes())
		printBinary(abSumCal.Bytes())
	}

	{
		cSum := new(big.Int).SetBytes(cs[0])
		if csSign[0] < 0 {
			cSum = new(big.Int).Neg(cSum)
		}
		for i := 1; i < K; i++ {
			if csSign[i] < 0 {
				cSum = new(big.Int).Sub(cSum, new(big.Int).SetBytes(cs[i]))
			} else {
				cSum = new(big.Int).Add(cSum, new(big.Int).SetBytes(cs[i]))
			}
		}

		aSum := new(big.Int).SetBytes(as[0][:])
		for i := 1; i < K; i++ {
			aSum = new(big.Int).Add(aSum, new(big.Int).SetBytes(as[i][:]))
		}

		bSum := new(big.Int).SetBytes(bs[0][:])
		for i := 1; i < K; i++ {
			bSum = new(big.Int).Add(bSum, new(big.Int).SetBytes(bs[i][:]))
		}

		cSumCal := new(big.Int).Mul(aSum, bSum)

		fmt.Println("a * b:")
		printBinary(cSum.Bytes())
		printBinary(cSumCal.Bytes())
	}
}

func printBinary(array []byte) {
	for i := 0; i < len(array); i++ {
		fmt.Printf("%02x", array[i])
	}
	fmt.Printf("\n")
}

func main() {
	master_key_share_generate()
	user_familiar_key_generate()
	verify_cs()
}
