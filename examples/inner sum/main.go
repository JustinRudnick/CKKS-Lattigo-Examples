// Package main implements an example of smooth function approximation using Chebyshev polynomial interpolation.
package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

func main() {
	var err error
	var params ckks.Parameters

	//------------------
	// Initialization
	//------------------

	// 128-bit secure parameters enabling depth-7 circuits.
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

	slots := 1 << params.LogN()
	values1 := make([]float64, slots)
	fillNaturalNumbers(values1)

	fmt.Printf("values1: %v\n", values1)

	// We generate the `rlwe.GaloisKey`s element that corresponds to these galois elements.
	// And we update the evaluator's `rlwe.EvaluationKeySet` with the new keys.
	batches := 1
	terms := slots / batches //terms per batch
	eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batches, terms), sk)...))

	pt1 := ckks.NewPlaintext(params, params.MaxLevel()) // Allocates a plaintext at the max level.

	//------------------
	// Encoding
	//------------------

	if err = ecd.Encode(values1, pt1); err != nil {
		panic(err)
	}

	//------------------
	// Encryption
	//------------------

	var ct1 *rlwe.Ciphertext
	if ct1, err = enc.EncryptNew(pt1); err != nil {
		panic(err)
	}

	//------------------
	// Evaluate Operation
	//------------------
	println("evaluate ---- inner sum ----")

	if err := eval.InnerSum(ct1, batches, terms, ct1); err != nil {
		panic(err)
	}

	//------------------
	// Decryption & Decoding
	//------------------

	dec.Decrypt(ct1, pt1)
	result := make([]float64, pt1.Slots())
	err = ecd.Decode(pt1, result)

	fmt.Printf("result: %v\n", result)
}

func fillRandom(v []float64, domain [2]float64) {
	for i := range v {
		v[i] = sampling.RandFloat64(domain[0], domain[1])
	}
}

func fillNaturalNumbers(v []float64) {
	for i := range v {
		v[i] = float64(i)
	}
}
