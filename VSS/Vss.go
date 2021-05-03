package VSS

import (
	"familiar_address/miracl/core"
	"familiar_address/miracl/core/BN254_FA"
)

func Vss(secret [32]byte, ids [][32]byte, rng *core.RAND, t int, n int) (error int, polysRet [][32]byte, polyPointsRet [][65]byte, sharesRet [][32]byte) {
	if len(ids) != n {
		return -1, nil, nil, nil
	}

	polys := make([][32]byte, t)
	polysBig := make([]*BN254_FA.BIG, t)
	polyPoints := make([][65]byte, t)

	G := BN254_FA.ECP_generator()
	s := BN254_FA.FromBytes(secret[:])
	BN254_FA.G1mul(G, s).ToBytes(polyPoints[0][:], true) // check?

	polys[0] = secret
	polysBig[0] = s

	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)

	for i := 0; i < t-1; i++ {
		tem := BN254_FA.Randomnum(r, rng)

		tem.ToBytes(polys[i+1][:])
		polysBig[i+1] = tem
		BN254_FA.G1mul(G, tem).ToBytes(polyPoints[i+1][:], true)
	}

	shares := make([][32]byte, n)

	for i := 0; i < n; i++ {
		shareVal := calculatePolynomial(polysBig, ids[i][:])
		shares[i] = shareVal
	}

	return 1, polys, polyPoints, shares
}

func calculatePolynomial(polysBig []*BN254_FA.BIG, id []byte) (ret [32]byte) {
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)

	lastIndex := len(polysBig) - 1
	result := polysBig[lastIndex]
	idBig := BN254_FA.FromBytes(id)

	for i := lastIndex - 1; i >= 0; i-- {
		result = BN254_FA.Modmuladd(result, idBig, polysBig[i], r)
	}

	result.ToBytes(ret[:])
	return
}

func Verify(share [32]byte, id [32]byte, polyPoints [][65]byte) bool {
	G := BN254_FA.ECP_generator()
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)

	shareBig := BN254_FA.FromBytes(share[:])
	idBig := BN254_FA.FromBytes(id[:])

	sharePoint := BN254_FA.G1mul(G, shareBig)
	computeSharePoint := BN254_FA.ECP_fromBytes(polyPoints[0][:])
	if !BN254_FA.G1member(computeSharePoint) {
		return false
	}

	for i := 1; i < len(polyPoints); i++ {
		temPoint := BN254_FA.ECP_fromBytes(polyPoints[i][:])
		temPoint = BN254_FA.G1mul(temPoint, idBig)
		computeSharePoint.Add(temPoint)

		idBig = BN254_FA.Modmul(idBig, BN254_FA.FromBytes(id[:]), r)
	}

	if sharePoint.Equals(computeSharePoint) {
		return true
	} else {
		return false
	}
}

func Combine(shares [][32]byte, ids [][32]byte) (error int, secret [32]byte) {
	var ret [32]byte

	if len(shares) != len(ids) {
		return -1, ret
	}

	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)

	idsBig := make([]*BN254_FA.BIG, len(ids))
	for i := 0; i < len(ids); i++ {
		idsBig[i] = BN254_FA.FromBytes(ids[i][:])
	}

	secretBig := BN254_FA.NewBIG()

	for i := 0; i < len(shares); i++ {
		times := BN254_FA.NewBIG()
		times.One()

		for j := 0; j < len(ids); j++ {
			if j != i {
				sub := BN254_FA.Modsub(idsBig[j], idsBig[i], r)
				sub.Invmodp(r)
				div := BN254_FA.Modmul(idsBig[j], sub, r)
				times = BN254_FA.Modmul(times, div, r)
			}
		}

		// calculate sum(f(x) * times())
		secretBig = BN254_FA.Modmuladd(BN254_FA.FromBytes(shares[i][:]), times, secretBig, r)
	}

	secretBig.ToBytes(ret[:])
	return 1, ret
}

func Combine2(shares [][32]byte, ids [][32]byte) (error int, secret [32]byte) {
	var ret [32]byte

	if len(shares) != len(ids) {
		return -1, ret
	}

	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)

	idsBig := make([]*BN254_FA.BIG, len(ids))
	for i := 0; i < len(ids); i++ {
		idsBig[i] = BN254_FA.FromBytes(ids[i][:])
	}

	secretBig := BN254_FA.NewBIG()

	for i := 0; i < len(shares); i++ {
		var temIds [][32]byte
		for j := 0; j < len(ids); j++ {
			if j != i {
				temIds = append(temIds, ids[j])
			}
		}

		lagPolyBytes := GetLagrangePolynomial(temIds, ids[i])
		lagPolyBig := BN254_FA.FromBytes(lagPolyBytes[:])

		// calculate sum(f(x) * times())
		secretBig = BN254_FA.Modmuladd(BN254_FA.FromBytes(shares[i][:]), lagPolyBig, secretBig, r)
	}

	secretBig.ToBytes(ret[:])
	return 1, ret
}

func GetLagrangePolynomial(ids [][32]byte, id [32]byte) (lagrangePoly [32]byte) {
	r := BN254_FA.NewBIGints(BN254_FA.CURVE_Order)

	idsBig := make([]*BN254_FA.BIG, len(ids))
	for i := 0; i < len(ids); i++ {
		idsBig[i] = BN254_FA.FromBytes(ids[i][:])
	}
	idBig := BN254_FA.FromBytes(id[:])

	lagPoly := BN254_FA.NewBIG()
	lagPoly.One()

	for i := 0; i < len(ids); i++ {
		sub := BN254_FA.Modsub(idsBig[i], idBig, r)
		sub.Invmodp(r)
		div := BN254_FA.Modmul(idsBig[i], sub, r)
		lagPoly = BN254_FA.Modmul(lagPoly, div, r)
	}

	var lagPolyBytes [32]byte
	lagPoly.ToBytes(lagPolyBytes[:])

	return lagPolyBytes
}
