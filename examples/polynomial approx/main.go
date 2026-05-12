// Package main implements an example of smooth function approximation using Chebyshev polynomial interpolation.
package main

import (
	"math/big"

	"github.com/JustinRudnick/CKKS-Lattigo-Examples/printing"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func main() {
	var err error
	var params ckks.Parameters

	//------------------
	// Initialization
	//------------------

	// 128-bit secure parameters enabling depth-7 circuits.
	// LogN:14, LogQP: 431.
	if params, err = ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:            4,                                     // log2(ring degree)
			LogQ:            []int{55, 45, 45, 45, 45, 45, 45, 45}, // log2(primes Q) (ciphertext modulus)
			LogP:            []int{61},                             // log2(primes P) (auxiliary modulus)
			LogDefaultScale: 45,                                    // log2(scale)
			RingType:        ring.ConjugateInvariant,
		}); err != nil {
		panic(err)
	}

	kgen := rlwe.NewKeyGenerator(params)              // Key Generator
	sk := kgen.GenSecretKeyNew()                      // Secret Key
	ecd := ckks.NewEncoder(params)                    // Encoder
	enc := rlwe.NewEncryptor(params, sk)              // Encryptor
	dec := rlwe.NewDecryptor(params, sk)              // Decryptor
	rlk := kgen.GenRelinearizationKeyNew(sk)          // Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)           // Evaluation Key Set with the Relinearization Key
	eval := ckks.NewEvaluator(params, evk)            // Evaluator
	polyEval := polynomial.NewEvaluator(params, eval) // Instantiates the polynomial evaluator

	// Samples values in [-K, K]
	sample_domain := [2]float64{-25.0, 25.0}

	// Allocates a plaintext at the max level.
	pt := ckks.NewPlaintext(params, params.MaxLevel())

	values := make([]float64, pt.Slots())
	fillRandom(values, sample_domain)

	//------------------
	// Encoding
	//------------------

	if err = ecd.Encode(values, pt); err != nil {
		panic(err)
	}

	//------------------
	// Encryption
	//------------------

	var ct *rlwe.Ciphertext
	if ct, err = enc.EncryptNew(pt); err != nil {
		panic(err)
	}

	//------------------
	// Evaluate Polynomial
	//------------------

	coeffs := []float64{0, 0, 1} // f(x) = x^2
	polynom := bignum.NewPolynomial(bignum.Monomial, coeffs, sample_domain)
	poly_approx := polynomial.NewPolynomial(polynom)

	if ct, err = polyEval.Evaluate(ct, poly_approx, params.DefaultScale()); err != nil {
		panic(err)
	}

	//------------------
	// Decryption & Decoding
	//------------------

	pt = dec.DecryptNew(ct)
	have := make([]float64, pt.Slots())
	ecd.Decode(pt, have)

	want := make([]float64, pt.Slots())
	for i := range pt.Slots() {
		var tmp *big.Float = bignum.NewFloat(values[i], 64)
		println((*tmp).Float64())
		want[i], _ = polynom.Evaluate(tmp).Real().Float64()
	}

	printing.PrintSlots(want, have, pt.Slots())

}

func fillRandom(v []float64, domain [2]float64) {
	for i := range v {
		v[i] = sampling.RandFloat64(domain[0], domain[1])
	}
}

func fillNaturalNumbers(v []float64) {
	for i := range v {
		v[i] = float64(i + 1)
	}
}
