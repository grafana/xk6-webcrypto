package webcrypto

import (
	"github.com/dop251/goja"
)

type Sha struct {
	Algorithm
}

// NewSha .
func NewSha(rt *goja.Runtime, alg string, _ goja.Value) (NormalizedAlgorithm, error) {
	if alg == "" {
		return nil, NewError(0, SyntaxError, "algorithm is required")
	}

	return Sha{Algorithm{alg}}, nil
}
