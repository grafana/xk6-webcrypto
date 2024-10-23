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

func (p PBKDF2Params) DeriveKey() (CryptoKeyGenerationResult, error) {
	return nil, nil
}

// EcKeyImportParams represents the object that should be passed as the algorithm parameter
// into `SubtleCrypto.ImportKey` or `SubtleCrypto.UnwrapKey`, when generating any elliptic-curve-based
// key pair: that is, when the algorithm is identified as either of ECDSA or ECDH.
type PBKDF2KeyImportParams struct {
	Algorithm
}

func newPBKDF2KeyImportParams(rt *sobek.Runtime, normalized Algorithm, params sobek.Value) (*PBKDF2KeyImportParams, error) {

	return &PBKDF2KeyImportParams{
		Algorithm: normalized,
	}, nil
}

func (keyParams PBKDF2KeyImportParams) ImportKey(format KeyFormat, keyData []byte, keyUsages []CryptoKeyUsage) (*CryptoKey, error) {
	for _, usage := range keyUsages {
		switch usage {
		case EncryptCryptoKeyUsage, DecryptCryptoKeyUsage, WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage, DeriveBitsCryptoKeyUsage, DeriveKeyCryptoKeyUsage:
			continue
		default:
			return nil, NewError(SyntaxError, "invalid key usage: "+usage)
		}
	}
	return &CryptoKey{
		Algorithm: PBKDF2KeyAlgorithm{
			Algorithm: keyParams.Algorithm,
		},
		Type:   SecretCryptoKeyType,
		handle: keyData,
	}, nil
}

// Ensure that EcKeyImportParams implements the KeyImporter interface.
var _ KeyImporter = &PBKDF2KeyImportParams{}

// PBKDF2KeyAlgorithm is the algorithm for PBKDF2 keys as defined in the [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#dfn-PBKDF2KeyAlgorithm //TODO: update this to something real
type PBKDF2KeyAlgorithm struct {
	Algorithm
}

var _ hasAlg = (*PBKDF2KeyAlgorithm)(nil)

func (aka PBKDF2KeyAlgorithm) alg() string {
	return aka.Name
}
