// Package main implements an example of smooth function approximation using Chebyshev polynomial interpolation.
package main

import (
	"github.com/JustinRudnick/CKKS-Lattigo-Examples/printing"
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

	sample_domain := [2]float64{-25, 25}

	slots := 1 << params.LogN()
	values1 := make([]float64, slots)
	values2 := make([]float64, slots)
	fillRandom(values1, sample_domain)
	fillRandom(values2, sample_domain)

	pt1 := ckks.NewPlaintext(params, params.MaxLevel()) // Allocates a plaintext at the max level.
	pt2 := ckks.NewPlaintext(params, params.MaxLevel())

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

	var ct1 *rlwe.Ciphertext
	var ct2 *rlwe.Ciphertext
	if ct1, err = enc.EncryptNew(pt1); err != nil {
		panic(err)
	}
	if ct2, err = enc.EncryptNew(pt2); err != nil {
		panic(err)
	}

	//------------------
	// Evaluate Operation
	//------------------

	//multiply
	if err = eval.MulRelin(ct1, ct2, ct1); err != nil {
		panic(err)
	}
	if err = eval.Rescale(ct1, ct1); err != nil {
		panic(err)
	}

	//evaluate inner sum

	// We generate the `rlwe.GaloisKey`s element that corresponds to these galois elements.
	// And we update the evaluator's `rlwe.EvaluationKeySet` with the new keys.

	batches := 1
	terms := slots / batches //terms per batch
	eval = eval.WithKey(rlwe.NewMemEvaluationKeySet(rlk, kgen.GenGaloisKeysNew(params.GaloisElementsForInnerSum(batches, terms), sk)...))

	if err := eval.InnerSum(ct1, batches, terms, ct1); err != nil {
		panic(err)
	}

	//------------------
	// Decryption & Decoding
	//------------------

	dec.Decrypt(ct1, pt1)
	have := make([]float64, pt1.Slots())
	err = ecd.Decode(pt1, have)

	want := make([]float64, pt1.Slots())
	var sum float64 = 0
	for i := range pt1.Slots() {
		sum += values1[i] * values2[i]
	}
	for i := range pt1.Slots() {
		want[i] = sum
	}

	printing.PrintSlots(want, have, pt1.Slots())

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
