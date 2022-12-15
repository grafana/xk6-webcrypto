package webcrypto

import (
	"crypto"
	"fmt"
	"hash"
	"strings"

	"github.com/dop251/goja"
)

// Algorithm represents
type Algorithm struct {
	Name AlgorithmIdentifier `json:"name"`
}

// NormalizedName returns the normalized algorithm identifier.
// It implements the NormalizedIdentifier interface.
func (a Algorithm) NormalizedName() AlgorithmIdentifier {
	return a.Name
}

// NewAlgorithm creates a new Algorithm instance from a goja.Value.
func NewAlgorithm(rt *goja.Runtime, v goja.Value) (Algorithm, error) {
	if v == nil {
		return Algorithm{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params Algorithm
	if err := rt.ExportTo(v, &params); err != nil {
		return Algorithm{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	if err := params.Validate(); err != nil {
		return Algorithm{}, err
	}

	if err := params.Normalize(); err != nil {
		return Algorithm{}, err
	}

	return params, nil
}

// Validate validates the Algorithm instance fits the specifications
// requirements. It implements the Validator interface.
func (a Algorithm) Validate() error {
	if a.Name == "" {
		return NewError(0, SyntaxError, "name property is required")
	}

	if !IsAlgorithm(a.Name) && !IsHashAlgorithm(a.Name) {
		return NewError(0, NotSupportedError, "algorithm name is not supported")
	}

	return nil
}

// Normalize normalizes the Algorithm instance. It implements the Normalizer
// interface.
func (a *Algorithm) Normalize() error {
	a.Name = NormalizeAlgorithmName(a.Name)
	return nil
}

// AlgorithmIdentifier represents the name of an algorithm.
// As defined by the [specification]
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string by goja.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#algorithm-dictionary
type AlgorithmIdentifier = string

const (
	// RSASsaPkcs1v15 represents the RSA-SHA1 algorithm.
	RSASsaPkcs1v15 = "RSASSA-PKCS1-v1_5"

	// RSAPss represents the RSA-PSS algorithm.
	RSAPss = "RSA-PSS"

	// RSAOaep represents the RSA-OAEP algorithm.
	RSAOaep = "RSA-OAEP"

	// HMAC represents the HMAC algorithm.
	HMAC = "HMAC"

	// AESCtr represents the AES-CTR algorithm.
	AESCtr = "AES-CTR"

	// AESCbc represents the AES-CBC algorithm.
	AESCbc = "AES-CBC"

	// AESGcm represents the AES-GCM algorithm.
	AESGcm = "AES-GCM"

	// AESKw represents the AES-KW algorithm.
	AESKw = "AES-KW"

	// ECDSA represents the ECDSA algorithm.
	ECDSA = "ECDSA"

	// ECDH represents the ECDH algorithm.
	ECDH = "ECDH"
)

// HashAlgorithmIdentifier represents the name of a hash algorithm.
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string under the hood by goja.
type HashAlgorithmIdentifier = AlgorithmIdentifier

const (
	// Sha1 represents the SHA-1 algorithm.
	Sha1 HashAlgorithmIdentifier = "SHA-1"

	// Sha256 represents the SHA-256 algorithm.
	Sha256 = "SHA-256"

	// Sha384 represents the SHA-384 algorithm.
	Sha384 = "SHA-384"

	// Sha512 represents the SHA-512 algorithm.
	Sha512 = "SHA-512"
)

// Hasher returns the appropriate hash.Hash for the given algorithm.
func Hasher(algorithm HashAlgorithmIdentifier) (func() hash.Hash, error) {
	switch algorithm {
	case Sha1:
		return crypto.SHA1.New, nil
	case Sha256:
		return crypto.SHA256.New, nil
	case Sha384:
		return crypto.SHA384.New, nil
	case Sha512:
		return crypto.SHA512.New, nil
	}

	return nil, NewError(0, ImplementationError, fmt.Sprintf("unsupported hash algorithm: %s", algorithm))
}

// IsAlgorithm returns true if the given algorithm is supported by the library.
func IsAlgorithm(algorithm string) bool {
	algorithms := [...]AlgorithmIdentifier{
		// RSA
		RSASsaPkcs1v15,
		RSAPss,
		RSAOaep,

		// HMAC
		HMAC,

		// AES
		AESCtr,
		AESCbc,
		AESGcm,
		AESKw,

		// ECDSA
		ECDSA,

		// ECDH
		ECDH,
	}

	for _, alg := range algorithms {
		if strings.EqualFold(alg, algorithm) {
			return true
		}
	}

	return false
}

// IsHashAlgorithm returns true if the given cryptographic hash algorithm
// name is valid and supported by the library.
func IsHashAlgorithm(algorithm string) bool {
	algorithms := [...]HashAlgorithmIdentifier{
		Sha1,
		Sha256,
		Sha384,
		Sha512,
	}

	for _, alg := range algorithms {
		if strings.EqualFold(alg, algorithm) {
			return true
		}
	}

	return false
}
