package webcrypto

import "github.com/grafana/sobek"

func newPBKDF2KeyDeriveParams(rt *sobek.Runtime, normalized Algorithm, params sobek.Value) (*PBKDF2Params, error) {
	//TODO: add implmentation
	hashValue, err := traverseObject(rt, params, "hash")
	if err != nil {
		return nil, NewError(SyntaxError, "could not get hash from algorithm parameter")
	}

	normalizedHash, err := normalizeAlgorithm(rt, hashValue, OperationIdentifierDeriveKey)
	if err != nil {

		return nil, err
	}
	return &PBKDF2Params{
		Name: normalized.Name,
		Hash: normalizedHash.Name,
		Salt: []byte{},
	}, nil
}
