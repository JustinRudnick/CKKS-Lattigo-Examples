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

	_, ecd, enc, dec, eval := initTools(params)

	slots := 1 << params.LogN()
	sample_domain := [2]float64{-25.0, 25.0}
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
	if ct1, err = enc.EncryptNew(pt1); err != nil {
		panic(err)
	}
	var ct2 *rlwe.Ciphertext
	if ct2, err = enc.EncryptNew(pt2); err != nil {
		panic(err)
	}

	//------------------
	// Evaluate Polynomial
	//------------------

	if err := eval.Mul(ct1, ct2, ct1); err != nil {
		panic(err)
	}
	if err := eval.Relinearize(ct1, ct1); err != nil {
		panic(err)
	}
	if err := eval.Rescale(ct1, ct1); err != nil {
		panic(err)
	}

	pt1 = dec.DecryptNew(ct1)
	have := make([]float64, pt1.Slots())
	err = ecd.Decode(pt1, have)

	want := make([]float64, pt1.Slots())
	for i := range slots {
		want[i] = values1[i] * values2[i]
	}

	printing.PrintSlots(want, have, slots)
}

func initTools(params ckks.Parameters) (sk *rlwe.SecretKey, ecd *ckks.Encoder, enc *rlwe.Encryptor, dec *rlwe.Decryptor, eval *ckks.Evaluator) {
	kgen := rlwe.NewKeyGenerator(params)     // Key Generator
	sk = kgen.GenSecretKeyNew()              // Secret Key
	ecd = ckks.NewEncoder(params)            // Encoder
	enc = rlwe.NewEncryptor(params, sk)      // Encryptor
	dec = rlwe.NewDecryptor(params, sk)      // Decryptor
	rlk := kgen.GenRelinearizationKeyNew(sk) // Relinearization Key
	evk := rlwe.NewMemEvaluationKeySet(rlk)  // Evaluation Key Set with the Relinearization Key
	eval = ckks.NewEvaluator(params, evk)    // Evaluator

	return sk, ecd, enc, dec, eval
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
