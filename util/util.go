package util

import (
	"errors"
	"math"
)

// get absolute error (AE)
//
// AE = abs(want - have)
func getAE(want float64, have float64) (res float64) {
	return math.Abs(want - have)
}

// get mean absolute error (MAE) of the first n elements
//
// MAE = sum(AE)/n
func getMAE(want []float64, have []float64, n int) (res float64, err error) {
	return _getMPowE(want, have, n, 1)
}

// get mean square error (MSE) of the first n elements
//
// MSE = sum(AE * AE)/n
func getMSE(want []float64, have []float64, n int) (res float64, err error) {
	return _getMPowE(want, have, n, 2)
}

// get root mean square error (MSE) of the first n elements
//
// MSE = sqrt(sum(AE * AE)/n)
func getRMSE(want []float64, have []float64, n int) (res float64, err error) {
	if res, err = getMSE(want, have, n); err != nil {
		return 0, err
	}
	return math.Sqrt(res), nil
}

// get relative error (RE) of the first n elements
//
// RE = |have - want|/|want|
func getRE(want float64, have float64) (res float64) {
	return math.Abs(want-have) / math.Abs(want)
}

// get relative percentage  error (RPE) of the first n elements
//
// RPE = 100 * RE
func getRPE(want float64, have float64) (res float64) {
	return 100 * getRE(want, have)
}

// get the maximum absolue error (MaxAE) of the first n elements
//
// MaxAE = max(getAE...)
func getMaxAE(want []float64, have []float64, n int) (res float64, err error) {
	return _getMaxE(want, have, n, getAE)
}

// get the maximum relative error (MaxRE) of the first n elements
//
// MaxRE = max(getRE...)
func getMaxRE(want []float64, have []float64, n int) (res float64, err error) {
	return _getMaxE(want, have, n, getRE)
}

// get mean absolute percentage error (MAPE) of the first n elements
//
// MAPE = 100 * MAE
func getMAPE(want []float64, have []float64, n int) (res float64, err error) {
	if res, err = getMAE(want, have, n); err != nil {
		return 0, err
	}
	return 100 * res, nil
}

func getStdDeviation(want []float64, have []float64, n int) (res float64, err error) {
	if len(want) < n || len(have) < n {
		err = errors.New("buffer overflow error.")
		return 0, err
	}

	var arithmeticMean float64
	if arithmeticMean, err = _getArithmeticMean(want, n); err != nil {
		return 0, err
	}

	var sum float64 = 0
	for i := range n {
		sum += math.Pow(have[i]-arithmeticMean, 2)
	}

	return math.Sqrt(sum / float64(n)), nil
}

func getVariance(want []float64, have []float64, n int) (res float64, err error) {
	if res, err = getStdDeviation(want, have, n); err != nil {
		return 0, err
	}
	return math.Pow(res, 2), nil
}

//########################## print functions #####################################################

func printSlot(want float64, have float64) {
	println(want, "\t", have, "\t", getAE(want, have), "\t", getRE(want, have))
}

func printSlots(want []float64, have []float64, n int) {

	println("WANT\t\t\tHAVE\t\t\tabs. ERROR\t\t\trel. ERROR")

	for i := range n {
		printSlot(want[i], have[i])
	}

	println()
	println("MAE:\t\t", _printValuetNoErr(want, have, n, getMAE))
	println("MSE:\t\t", _printValuetNoErr(want, have, n, getMSE))
	println("RMSE:\t\t", _printValuetNoErr(want, have, n, getRMSE))
	println("Max AE:\t\t", _printValuetNoErr(want, have, n, getMaxAE))
	println("Max RE:\t\t", _printValuetNoErr(want, have, n, getMaxRE))
	println("std. deviation:\t", _printValuetNoErr(want, have, n, getStdDeviation))
	println("variance:\t", _printValuetNoErr(want, have, n, getVariance))
}

//########################## helper functions ####################################################

// get mean pow error (MPowE) of the first n elements
//
// MPowE = sum(AE^pow)/n
func _getMPowE(want []float64, have []float64, n int, pow float64) (res float64, err error) {

	if len(want) < n || len(have) < n {
		err = errors.New("buffer overflow error.")
		return 0, err
	}

	var sum float64 = 0
	for i := range n {
		sum += math.Pow(getAE(want[i], have[i]), pow)
	}

	return sum / float64(n), nil
}

func _getMaxE(want []float64, have []float64, n int, fnc func(want float64, have float64) (res float64)) (res float64, err error) {
	if len(want) < n || len(have) < n {
		err = errors.New("buffer overflow error.")
		return 0, err
	}

	var max float64 = 0
	for i := range n {
		max = math.Max(fnc(want[i], have[i]), max)
	}
	return max, nil
}

func _getArithmeticMean(slice []float64, n int) (res float64, err error) {
	if len(slice) < n {
		err = errors.New("buffer overflow error.")
		return 0, err
	}

	var sum float64 = 0
	for i := range n {
		sum += slice[i]
	}
	return sum, nil

}

func _printValuetNoErr(want []float64, have []float64, n int, fnc func(want []float64, have []float64, n int) (res float64, err error)) (value float64) {
	var err error

	if value, err = fnc(want, have, n); err != nil {
		return math.NaN()
	}

	return value
}
