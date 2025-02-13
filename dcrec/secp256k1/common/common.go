package common

import (
	"crypto/rand"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func ScalarBaseMultWithBlinding(k *secp256k1.ModNScalar) (*secp256k1.JacobianPoint, error) {
	// Generate a random blinding factor r
	r := new(secp256k1.ModNScalar)
	var rBytes [32]byte
	if _, err := rand.Read(rBytes[:]); err != nil {
		return nil, err
	}
	r.SetByteSlice(rBytes[:])

	// Compute (k+r)G
	kr := new(secp256k1.ModNScalar).Set(k).Add(r)
	var krG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(kr, &krG)

	// Compute -rG
	rNeg := new(secp256k1.ModNScalar).Set(r).Negate()
	var rNegG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(rNeg, &rNegG)

	// Convert to affine coordinates so that the addition is constant time
	krG.ToAffine()
	rNegG.ToAffine()

	// Add (k+r)G and -rG to get kG
	var R secp256k1.JacobianPoint
	secp256k1.AddNonConst(&krG, &rNegG, &R)

	return &R, nil
}
