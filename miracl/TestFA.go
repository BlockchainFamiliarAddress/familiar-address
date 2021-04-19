package main

import (
	"familiar_address/Commit"
	"familiar_address/SchnorrZK"
	"familiar_address/VSS"
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
	"fmt"
	"strconv"
)

var N int = 5 // all number of PKG
var T int = 3 // threshold

var seeds = make([][100]byte, N)
var rngs = make([]*core.RAND, N)

var ids = make([][32]byte, N)

var Sks = make([][32]byte, N) // private key
var Pks = make([][65]byte, N) // public key

var polyss = make([][][32]byte, N)
var polyPointss = make([][][65]byte, N)
var sharess = make([][][32]byte, N)

var msgSks = make([][32]byte, N)
var Es = make([][32]byte, N)
var Ss = make([][32]byte, N)

var secretss = make([][][]byte, N)
var Cs = make([][32]byte, N)
var Ds = make([][][]byte, N)

var MSks = make([][32]byte, N)
var MPk [65]byte

func familiar_address() {
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)
	G2 := BN254_FA.ECP2_generator()

	// every PKG generates his own seed (saved in seeds, 100byte) used in PRNG
	// every PKG generates his own PRNG (saved in rngs)
	fmt.Println("\nevery PKG generates his own seed (saved in seeds, 100byte) used in PRNG")
	fmt.Println("every PKG generates his own PRNG (saved in rngs)")
	for i := 0; i < N; i++ {
		for j := 0; j < 100; j++ {
			seeds[i][j] = byte(i * j)
		}
	}

	for i := 0; i < N; i++ {
		rngs[i] = core.NewRAND()
		rngs[i].Seed(100, seeds[i][:])
	}

	// every PKG generates his id (saved in ids, 32byte)
	// every PKG generates his private key (saved in Sks, 32byte) and public key (saved in Pks, 65byte, compressed)
	fmt.Println("\nevery PKG generates his id (saved in ids, 32byte)")
	fmt.Println("every PKG generates his private key (saved in Sks, 32byte) and public key (saved in Pks, 65byte, compressed)")
	for i := 0; i < N; i++ {
		BN254_FA.Randomnum(r, rngs[i]).ToBytes(ids[i][:])

		res := BN254_FA.KeyPairGenerate(rngs[i], Sks[i][:], Pks[i][:])
		if res != 0 {
			fmt.Printf(strconv.Itoa(i) + "-th PKG, Failed to generate keys\n")
			return
		}
		fmt.Printf(strconv.Itoa(i) + "-th PKG, Private key : 0x")
		printBinary(Sks[i][:])
		fmt.Printf(strconv.Itoa(i) + "-th PKG, Public  key : 0x")
		printBinary(Pks[i][:])
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

	// every PKG generate schnorr zk proof (saved Es, Ss, 32byte) on random num (saved in msgSks, 32byte)
	fmt.Println("\nevery PKG generate schnorr zk proof (saved Es, Ss, 32byte) on random num (saved in msgSks, 32byte)")
	for i := 0; i < N; i++ {
		BN254_FA.Random(rngs[i]).ToBytes(msgSks[i][:])
		Es[i], Ss[i] = SchnorrZK.SZKProve(rngs[i], Sks[i], msgSks[i][:])

	}

	// every PKG commit (saved in Cs, 32byte, Ds) to Pks and the above schnorr zk proof (saved in secretss)
	fmt.Println("\nevery PKG commit (saved in Cs, 32byte, Ds) to Pks, above schnorr zk proof and polyPointss (saved in secretss)")
	for i := 0; i < N; i++ {
		secretss[i] = append(secretss[i], Pks[i][:])
		secretss[i] = append(secretss[i], Es[i][:])
		secretss[i] = append(secretss[i], Ss[i][:])
		secretss[i] = append(secretss[i], msgSks[i][:])
		for j := 0; j < T; j++ {
			secretss[i] = append(secretss[i], polyPointss[i][j][:])
		}

		Cs[i], Ds[i] = Commit.Commit(secretss[i], rngs[i])
	}

	// every PKG broadcasts the commit C
	// when all the PKG received the commit C, each PKG broadcast the commit D
	// every PKG validate the commit and validate the schnorr zk proof
	fmt.Println("\nevery PKG broadcasts the commit C")
	fmt.Println("when all the PKG received the commit C, each PKG broadcast the commit D")
	fmt.Println("\nevery PKG validate the commit and validate the schnorr zk proof")
	fmt.Println("validate commit:")
	for i := 0; i < N; i++ {
		fmt.Println(strconv.FormatBool(Commit.Verify(Cs[i], Ds[i])))
	}
	fmt.Println("\nvalidate schnorr zk proof:")
	for i := 0; i < N; i++ {
		fmt.Println(strconv.FormatBool(SchnorrZK.SZKVerify(Pks[i], msgSks[i][:], Es[i], Ss[i])))
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
			for k := 0; k < len(Ds[j][5:]); k++ {
				copy(tem[:], Ds[j][k+5])
				temArr = append(temArr, tem)
			}
			fmt.Println(strconv.FormatBool(VSS.Verify(sharess[j][i], ids[i], temArr)))
		}
	}

	// every PKG calculates the master private key share (saved in MSks, 32byte) and public key
	// 		example: PKG i calculate the sum of sharess[j][i] j in (0, N) as MSk
	fmt.Println("\nevery PKG calculates the master private key share (saved in MSks, 32byte) and public key (saved in MPk, 65byte)")
	fmt.Println("example: PKG i calculate the sum of sharess[j][i] j in (0, N) as MSk")
	MPkPoint := BN254_FA.ECP2_fromBytes(Ds[0][1])
	for i := 0; i < N; i++ {
		fmt.Println(strconv.Itoa(i) + "-th PKG's MSk:")
		MSk := BN254_FA.NewBIG()
		for j := 0; j < N; j++ {
			temBig := BN254_FA.FromBytes(sharess[j][i][:])
			MSk = BN254_FA.Modadd(MSk, temBig, r)
		}
		MSk.ToBytes(MSks[i][:])
		printBinary(MSks[i][:])

		temPoint := BN254_FA.ECP2_fromBytes(Ds[i][1])
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

func main() {
	familiar_address()
}

func printBinary(array []byte) {
	for i := 0; i < len(array); i++ {
		fmt.Printf("%02x", array[i])
	}
	fmt.Printf("\n")
}
