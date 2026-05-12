package printing

import (
	"errors"
	"math"
)

// get absolute error (AE)
//
// AE = abs(want - have)
func GetAE(want float64, have float64) (res float64) {
	return math.Abs(want - have)
}

// Get mean absolute error (MAE) of the first n elements
//
// MAE = sum(AE)/n
func GetMAE(want []float64, have []float64, n int) (res float64, err error) {
	return _GetMPowE(want, have, n, 1)
}

// Get mean square error (MSE) of the first n elements
//
// MSE = sum(AE * AE)/n
func GetMSE(want []float64, have []float64, n int) (res float64, err error) {
	return _GetMPowE(want, have, n, 2)
}

// Get root mean square error (MSE) of the first n elements
//
// MSE = sqrt(sum(AE * AE)/n)
func GetRMSE(want []float64, have []float64, n int) (res float64, err error) {
	if res, err = GetMSE(want, have, n); err != nil {
		return 0, err
	}
	return math.Sqrt(res), nil
}

// Get relative error (RE) of the first n elements
//
// RE = |have - want|/|want|
func GetRE(want float64, have float64) (res float64) {
	return math.Abs(want-have) / math.Abs(want)
}

// Get relative percentage  error (RPE) of the first n elements
//
// RPE = 100 * RE
func GetRPE(want float64, have float64) (res float64) {
	return 100 * GetRE(want, have)
}

// Get the maximum absolue error (MaxAE) of the first n elements
//
// MaxAE = max(GetAE...)
func GetMaxAE(want []float64, have []float64, n int) (res float64, err error) {
	return _GetMaxE(want, have, n, GetAE)
}

// Get the maximum relative error (MaxRE) of the first n elements
//
// MaxRE = max(GetRE...)
func GetMaxRE(want []float64, have []float64, n int) (res float64, err error) {
	return _GetMaxE(want, have, n, GetRE)
}

// Get mean absolute percentage error (MAPE) of the first n elements
//
// MAPE = 100 * MAE
func GetMAPE(want []float64, have []float64, n int) (res float64, err error) {
	if res, err = GetMAE(want, have, n); err != nil {
		return 0, err
	}
	return 100 * res, nil
}

func GetStdDeviation(want []float64, have []float64, n int) (res float64, err error) {
	if len(want) < n || len(have) < n {
		err = errors.New("buffer overflow error.")
		return 0, err
	}

	var arithmeticMean float64
	if arithmeticMean, err = _GetArithmeticMean(want, n); err != nil {
		return 0, err
	}

	var sum float64 = 0
	for i := range n {
		sum += math.Pow(have[i]-arithmeticMean, 2)
	}

	return math.Sqrt(sum / float64(n)), nil
}

func GetVariance(want []float64, have []float64, n int) (res float64, err error) {
	if res, err = GetStdDeviation(want, have, n); err != nil {
		return 0, err
	}
	return math.Pow(res, 2), nil
}

//########################## print functions #####################################################

func PrintSlot(want float64, have float64) {
	println(want, "\t", have, "\t", GetAE(want, have), "\t", GetRE(want, have))
}

func PrintSlots(want []float64, have []float64, n int) {

	println("WANT\t\t\tHAVE\t\t\tabs. ERROR\t\t\trel. ERROR")

	for i := range n {
		PrintSlot(want[i], have[i])
	}

	println()
	println("MAE:\t\t", _printValuetNoErr(want, have, n, GetMAE))
	println("MSE:\t\t", _printValuetNoErr(want, have, n, GetMSE))
	println("RMSE:\t\t", _printValuetNoErr(want, have, n, GetRMSE))
	println("Max AE:\t\t", _printValuetNoErr(want, have, n, GetMaxAE))
	println("Max RE:\t\t", _printValuetNoErr(want, have, n, GetMaxRE))
	println("std. deviation:\t", _printValuetNoErr(want, have, n, GetStdDeviation))
	println("variance:\t", _printValuetNoErr(want, have, n, GetVariance))
}

//########################## helper functions ####################################################

// Get mean pow error (MPowE) of the first n elements
//
// MPowE = sum(AE^pow)/n
func _GetMPowE(want []float64, have []float64, n int, pow float64) (res float64, err error) {

	if len(want) < n || len(have) < n {
		err = errors.New("buffer overflow error.")
		return 0, err
	}

	var sum float64 = 0
	for i := range n {
		sum += math.Pow(GetAE(want[i], have[i]), pow)
	}

	return sum / float64(n), nil
}

func _GetMaxE(want []float64, have []float64, n int, fnc func(want float64, have float64) (res float64)) (res float64, err error) {
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

func _GetArithmeticMean(slice []float64, n int) (res float64, err error) {
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
