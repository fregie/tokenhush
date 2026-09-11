package redact

import "github.com/fregie/tokenhush/pkg/extension"

// luhnConfidence is the fixed confidence for the Luhn detector. A valid Luhn
// checksum over 13-19 digits still leaves a ~1-in-10 false-positive rate for
// arbitrary numbers, hence the lower value.
const luhnConfidence = 0.9

// Card-number length bounds. Issuer identification numbers plus account
// numbers fit 13..19 digits.
const (
	luhnMinLen = 13
	luhnMaxLen = 19
)

// findLuhnDigits returns digit runs of 13..19 digits (single spaces or dashes
// allowed as group separators) that satisfy the Luhn checksum. Runs of one
// repeated digit are rejected: they are not issued account numbers and a run
// of zeros always passes Luhn.
func findLuhnDigits(content []byte) []span {
	var spans []span
	i := 0
	for i < len(content) {
		if !isASCIIDigit(content[i]) {
			i++
			continue
		}
		runStart := i
		lastDigit := i
		digits := 0
		for i < len(content) && (isASCIIDigit(content[i]) || content[i] == ' ' || content[i] == '-') {
			if isASCIIDigit(content[i]) {
				digits++
				lastDigit = i
			}
			i++
		}
		if digits < luhnMinLen || digits > luhnMaxLen {
			continue
		}
		normalized := stripNumberSeparators(content[runStart : lastDigit+1])
		if allSameDigit(normalized) || !luhnValid(normalized) {
			continue
		}
		spans = append(spans, span{start: runStart, end: lastDigit + 1})
	}
	return spans
}

// stripNumberSeparators drops spaces and dashes, keeping digits only.
func stripNumberSeparators(run []byte) []byte {
	out := make([]byte, 0, len(run))
	for _, b := range run {
		if isASCIIDigit(b) {
			out = append(out, b)
		}
	}
	return out
}

// allSameDigit reports whether every digit in digits is identical. digits is
// guaranteed non-empty by the caller.
func allSameDigit(digits []byte) bool {
	for _, b := range digits[1:] {
		if b != digits[0] {
			return false
		}
	}
	return true
}

// luhnValid reports whether digits (ASCII digits only) satisfies the Luhn
// checksum.
func luhnValid(digits []byte) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// NewLuhnDetector returns the built-in Inspector that flags Luhn-valid card
// numbers. It reports Type "credit_card" with confidence 0.9.
func NewLuhnDetector(opts ...Option) extension.Inspector {
	return newDetector(detectorIDLuhn, typeCreditCard, luhnConfidence, findLuhnDigits, opts)
}
