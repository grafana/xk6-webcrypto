package webcrypto

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/dop251/goja"
)

// Validator is an interface that can be implemented by types that need to
// validate their values.
type Validator interface {
	Validate() error
}

// NormalizedAlgorithm represents a normalized algorithm.
type NormalizedAlgorithm interface {
	NormalizedName() AlgorithmIdentifier
}

// NormalizeAlgorithm normalizes the given algorithm following the algorithm described in the WebCrypto [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#algorithm-normalization-normalize-an-algorithm
func NormalizeAlgorithm(rt *goja.Runtime, params goja.Value, op OperationIdentifier) (NormalizedAlgorithm, error) {
	// 1.
	possibleAlgs, ok := supportedAlgorithms[op]
	if !ok {
		return nil, NewError(0, ImplementationError, fmt.Sprintf("unsupported operation: %s", op))
	}

	// 2.
	rawName := extractAlgorithmName(rt, params)
	if rawName == "" {
		return nil, NewError(0, SyntaxError, "algorithm name is required")
	}

	// 3.
	alg := normalizeAlgorithmName(rawName)
	constructor, ok := possibleAlgs[alg]
	if !ok {
		return nil, NewError(0, NotSupportedError, fmt.Sprintf("unsupported algorithm: %s", rawName))
	}

	// 6.
	return constructor(rt, alg, params)
}

// extractAlgorithmName extracts the algorithm name from the given value.
// if no algorithm is specified, an empty string is returned.
func extractAlgorithmName(rt *goja.Runtime, v goja.Value) string {
	switch v.ExportType().Kind() {
	case reflect.String:
		return v.ToString().String()
	case reflect.Map, reflect.Struct:
		name := v.ToObject(rt).Get("name")
		if name == nil {
			return ""
		}

		return name.ToString().String()
	}

	return ""
}

// extractHash extracts the hash algorithm name from the given value.
// if no hash is specified, an empty string is returned.
func extractHash(rt *goja.Runtime, params goja.Value) string {
	v := params.ToObject(rt).Get("hash")
	if v == nil {
		return ""
	}

	switch v.ExportType().Kind() {
	case reflect.String:
		return v.ToString().String()
	case reflect.Map, reflect.Struct:
		// case when hash is an object, like {"name": "SHA-256"}
		hash := v.ToObject(rt).Get("name")
		if hash == nil {
			return ""
		}

		return hash.ToString().String()
	}

	return ""
}

type AlgConstructor func(rt *goja.Runtime, alg string, v goja.Value) (NormalizedAlgorithm, error)

// As defined by the [specification]
// [specification]: https://w3c.github.io/webcrypto/#algorithm-normalization-internal
//
//nolint:gochecknoglobals
var supportedAlgorithms = map[OperationIdentifier]map[AlgorithmIdentifier]AlgConstructor{
	OperationIdentifierDigest: {
		Sha1:   NewSha,
		Sha256: NewSha,
		Sha384: NewSha,
		Sha512: NewSha,
	},
	OperationIdentifierGenerateKey: {
		RSASsaPkcs1v15: NewRsaHashedKeyGenParams,
		RSAPss:         NewRsaHashedKeyGenParams,
		RSAOaep:        NewRsaHashedKeyGenParams,
		ECDSA:          NewEcKeyGenParams,
		ECDH:           NewEcKeyGenParams,
		HMAC:           NewHmacKeyGenParams,
		AESCtr:         NewAesKeyGenParams,
		AESCbc:         NewAesKeyGenParams,
		AESGcm:         NewAesKeyGenParams,
		AESKw:          NewAesKeyGenParams,
	},
}

// normalizeAlgorithmName returns the normalized algorithm name.
//
// As the algorithm name is case-insensitive, we normalize it to
// our internal representation.
func normalizeAlgorithmName(name string) AlgorithmIdentifier {
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
		if strings.EqualFold(name, alg) {
			return alg
		}
	}

	// it's not a known algorithm, so we return empty
	return ""
}

// NormalizeHashAlgorithmName returns the normalized hash algorithm name.
//
// As the algorithm name is case-insensitive, we normalize it to
// our internal representation.
func NormalizeHashAlgorithmName(name string) HashAlgorithmIdentifier {
	algorithms := [...]HashAlgorithmIdentifier{
		// SHA
		Sha1,
		Sha256,
		Sha384,
		Sha512,
	}

	for _, alg := range algorithms {
		if strings.EqualFold(name, alg) {
			return alg
		}
	}

	// it's not a known algorithm, so we return empty
	return ""
}

// OperationIdentifier represents the name of an operation.
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string by goja.
type OperationIdentifier = string

const (
	// OperationIdentifierSign represents the sign operation.
	OperationIdentifierSign OperationIdentifier = "sign"

	// OperationIdentifierVerify represents the verify operation.
	OperationIdentifierVerify OperationIdentifier = "verify"

	// OperationIdentifierEncrypt represents the encrypt operation.
	OperationIdentifierEncrypt OperationIdentifier = "encrypt"

	// OperationIdentifierDecrypt represents the decrypt operation.
	OperationIdentifierDecrypt OperationIdentifier = "decrypt"

	// OperationIdentifierDeriveBits represents the deriveBits operation.
	OperationIdentifierDeriveBits OperationIdentifier = "deriveBits"

	// OperationIdentifierDeriveKey represents the deriveKey operation.
	OperationIdentifierDeriveKey OperationIdentifier = "deriveKey"

	// OperationIdentifierWrapKey represents the wrapKey operation.
	OperationIdentifierWrapKey OperationIdentifier = "wrapKey"

	// OperationIdentifierUnwrapKey represents the unwrapKey operation.
	OperationIdentifierUnwrapKey OperationIdentifier = "unwrapKey"

	// OperationIdentifierImportKey represents the importKey operation.
	OperationIdentifierImportKey OperationIdentifier = "importKey"

	// OperationIdentifierExportKey represents the exportKey operation.
	OperationIdentifierExportKey OperationIdentifier = "exportKey"

	// OperationIdentifierGenerateKey represents the generateKey operation.
	OperationIdentifierGenerateKey OperationIdentifier = "generateKey"

	// OperationIdentifierDigest represents the digest operation.
	OperationIdentifierDigest OperationIdentifier = "digest"
)
