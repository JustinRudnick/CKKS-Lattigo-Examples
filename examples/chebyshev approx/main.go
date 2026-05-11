// Package main implements an example of smooth function approximation using Chebyshev polynomial interpolation.
package main

import (
	"fmt"
	"math"
	"math/big"

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

	println("Max Level:", params.MaxLevel())
	println("input vector slots:", pt.Slots())

	sigmoid := func(x float64) (y float64) {
		// return 1 / (math.Exp(-x) + 1)
		return math.Max(0, x) // ReLU
		// return 1 / x			//inv
	}

	polynomial_degree := 63
	sigmoid_approx := polynomial.NewPolynomial(GetChebyshevPoly(sample_domain, polynomial_degree, sigmoid))

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

	// Retrieves the change of basis y = scalar * x + constant
	scalar, constant := sigmoid_approx.ChangeOfBasis()

	// Performes the change of basis Standard -> Chebyshev
	if err := eval.Mul(ct, scalar, ct); err != nil {
		panic(err)
	}

	if err := eval.Add(ct, constant, ct); err != nil {
		panic(err)
	}

	if err := eval.Rescale(ct, ct); err != nil {
		panic(err)
	}

	// Evaluates the polynomial
	if ct, err = polyEval.Evaluate(ct, sigmoid_approx, params.DefaultScale()); err != nil {
		panic(err)
	}

	// Allocates a vector for the reference values and
	// evaluates the same circuit on the plaintext values
	sig_aprx_values := make([]float64, ct.Slots())
	sig_values := make([]float64, ct.Slots())
	for i := range ct.Slots() {
		sig_aprx_values[i], _ = sigmoid_approx.Evaluate(values[i])[0].Float64()
		sig_values[i] = sigmoid(values[i])
	}

	// Decrypts and print the stats about the precision.
	PrintPrecisionStats(params, ct, sig_values, ecd, dec)
	PrintPrecisionStats(params, ct, sig_aprx_values, ecd, dec)

}

// GetChebyshevPoly returns the Chebyshev polynomial approximation of f the
// in the passed domain for the given degree.
func GetChebyshevPoly(domain [2]float64, degree int, f64 func(x float64) (y float64)) bignum.Polynomial {

	FBig := func(x *big.Float) (y *big.Float) {
		xF64, _ := x.Float64()
		return new(big.Float).SetPrec(x.Prec()).SetFloat64(f64(xF64))
	}

	var prec uint = 128

	interval := bignum.Interval{
		A:     *bignum.NewFloat(domain[0], prec),
		B:     *bignum.NewFloat(domain[1], prec),
		Nodes: degree,
	}

	// Returns the polynomial.
	return bignum.ChebyshevApproximation(FBig, interval)
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
