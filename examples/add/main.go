// Package main implements an example of smooth function approximation using Chebyshev polynomial interpolation.
package main

import (
	"fmt"

	"github.com/JustinRudnick/CKKS-Lattigo-Examples/printing"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func main() {
	//------------------
	// Initialization
	//------------------

	var err error
	var params ckks.Parameters

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

	kgen := rlwe.NewKeyGenerator(params)     // Key Generator
	sk := kgen.GenSecretKeyNew()             // Secret Key
	ecd := ckks.NewEncoder(params)           // Encoder
	enc := rlwe.NewEncryptor(params, sk)     // Encryptor
	dec := rlwe.NewDecryptor(params, sk)     // Decryptor
	rlk := kgen.GenRelinearizationKeyNew(sk) // Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)  // Evaluation Key Set with the Relinearization Key
	eval := ckks.NewEvaluator(params, evk)   // Evaluator

	pt1 := ckks.NewPlaintext(params, params.MaxLevel()) // Allocates a plaintext at the max level.
	pt2 := ckks.NewPlaintext(params, params.MaxLevel())

	sample_domain := [2]float64{-25.0, 25.0}
	values1 := make([]float64, pt1.Slots())
	values2 := make([]float64, pt2.Slots())
	for i := range pt1.Slots() {
		values1[i] = sampling.RandFloat64(sample_domain[0], sample_domain[1])
		values2[i] = sampling.RandFloat64(sample_domain[0], sample_domain[1])
	}
	// fmt.Printf("values1: %v\n", values1)
	// fmt.Printf("values2: %v\n", values2)

	println("Operator: +")

	//------------------
	// Encoding
	//------------------

	if err = ecd.Encode(values1, pt1); err != nil {
		panic(err)
	}
	if err = ecd.Encode(values2, pt2); err != nil {
		panic(err)
	}

	//------------------
	// Encryption
	//------------------

	var ct1, ct2 *rlwe.Ciphertext
	if ct1, err = enc.EncryptNew(pt1); err != nil {
		panic(err)
	}
	if ct2, err = enc.EncryptNew(pt2); err != nil {
		panic(err)
	}

	//------------------
	// Evaluate Addition
	//------------------
	// ct-pt addition
	if err := eval.Add(ct1, pt2, ct1); err != nil {
		panic(err)
	}
	// ct-ct addition
	if err := eval.Add(ct1, ct2, ct2); err != nil {
		panic(err)
	}

	pt1 = dec.DecryptNew(ct1)
	result := make([]float64, pt1.Slots())
	err = ecd.Decode(pt1, result)

	for i := range pt1.Slots() {
		values1[i] += values2[i]
	}

	printing.PrintSlots(values1, result, 1<<params.LogN())

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
