// Package main implements an example of smooth function approximation using Chebyshev polynomial interpolation.
package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
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
	// for i := range values {
	// 	values[i] = sampling.RandFloat64(sample_domain[0], sample_domain[1])
	// }
	fillNaturalNumbers(values)

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
	sigmoid_approx := polynomial.NewPolynomial(polynom)

	if ct, err = polyEval.Evaluate(ct, sigmoid_approx, params.DefaultScale()); err != nil {
		panic(err)
	}

	// Allocates a vector for the reference values and
	// evaluates the same circuit on the plaintext values
	poly_aprx_values := make([]float64, ct.Slots())
	for i := range ct.Slots() {
		poly_aprx_values[i], _ = sigmoid_approx.Evaluate(values[i])[0].Float64()
	}

	// Decrypts and print the stats about the precision.
	PrintPrecisionStats(params, ct, poly_aprx_values, ecd, dec)
}

// PrintPrecisionStats decrypts, decodes and prints the precision stats of a ciphertext.
func PrintPrecisionStats(params ckks.Parameters, ct *rlwe.Ciphertext, want []float64, ecd *ckks.Encoder, dec *rlwe.Decryptor) {

	var err error

	// Decrypts the vector of plaintext values
	pt := dec.DecryptNew(ct)

	// Decodes the plaintext
	have := make([]float64, ct.Slots())
	if err = ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	// Pretty prints some values
	fmt.Printf("Have: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", have[i])
	}
	fmt.Printf("...\n")

	fmt.Printf("Want: ")
	for i := 0; i < 4; i++ {
		fmt.Printf("%20.15f ", want[i])
	}
	fmt.Printf("...\n")

	// Pretty prints the precision stats
	fmt.Println(ckks.GetPrecisionStats(params, ecd, dec, have, want, 0, false).String())
}

func fillNaturalNumbers(v []float64) {
	for i := range v {
		v[i] = float64(i + 1)
	}
}
