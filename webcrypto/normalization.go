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

// Normalizer is an interface that can be implemented by types that need to
// normalize their values.
type Normalizer interface {
	Normalize()
}

// NormalizedAlgorithm represents a normalized algorithm.
type NormalizedAlgorithm interface {
	NormalizedName() AlgorithmIdentifier
}

// NormalizeAlgorithm normalizes the given algorithm following the algorithm described in the WebCrypto [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#algorithm-normalization-normalize-an-algorithm
func NormalizeAlgorithm(rt *goja.Runtime, algorithm goja.Value, op OperationIdentifier) (NormalizedAlgorithm, error) {
	// 1.
	registeredAlgorithms, ok := supportedAlgorithms[op]
	if !ok {
		return Algorithm{}, NewError(0, ImplementationError, fmt.Sprintf("unsupported operation: %s", op))
	}

	// 2.
	var initialAlg Algorithm
	var err error

	switch algorithm.ExportType().Kind() {
	case reflect.String:
		obj := rt.NewObject()
		err = obj.Set("name", algorithm.Export())
		if err != nil {
			// 3.
			return Algorithm{}, NewError(0, ImplementationError, "unable to convert the string argument to an object")
		}
		return NormalizeAlgorithm(rt, obj, op)
	case reflect.Map, reflect.Struct:
		initialAlg, err = NewAlgorithm(rt, algorithm)
		if err != nil {
			// 3.
			return Algorithm{}, err
		}
	default:
		return Algorithm{}, NewError(0, SyntaxError, "unsupported algorithm type")
	}

	// 4.
	algName := initialAlg.Name

	// 5.
	var desiredType string
	algNameRegistered := false
	for key, value := range registeredAlgorithms {
		if strings.EqualFold(key, algName) {
			algName = key
			desiredType = value
			algNameRegistered = true
			break
		}
	}

	if !algNameRegistered {
		return Algorithm{}, NewError(0, NotSupportedError, fmt.Sprintf("unsupported algorithm name: %s", algName))
	}

	// No further operation is needed if the algorithm does not have a desired type.
	if desiredType == "" {
		return Algorithm{Name: algName}, nil
	}

	// 6.
	switch desiredType {
	case "AesKeyGenParams":
		return NewAesKeyGenParams(rt, algorithm)
	case "EcKeyGenParams":
		return NewEcKeyGenParams(rt, algorithm)
	case "HmacKeyGenParams":
		return NewHmacKeyGenParams(rt, algorithm)
	case "RsaHashedKeyGenParams":
		return NewRsaHashedKeyGenParams(rt, algorithm)
	default:
		return Algorithm{}, NewError(0, ImplementationError, fmt.Sprintf("unsupported algorithm type: %s", desiredType))
	}
}

// As defined by the [specification]
// [specification]: https://w3c.github.io/webcrypto/#algorithm-normalization-internal
//
//nolint:gochecknoglobals
var supportedAlgorithms = map[OperationIdentifier]map[AlgorithmIdentifier]string{
	OperationIdentifierDigest: {
		Sha1:   "",
		Sha256: "",
		Sha384: "",
		Sha512: "",
	},
	OperationIdentifierGenerateKey: {
		RSASsaPkcs1v15: "RsaHashedKeyGenParams",
		RSAPss:         "RsaHashedKeyGenParams",
		RSAOaep:        "RsaHashedKeyGenParams",
		ECDSA:          "EcKeyGenParams",
		ECDH:           "EcKeyGenParams",
		HMAC:           "HmacKeyGenParams",
		AESCtr:         "AesKeyGenParams",
		AESCbc:         "AesKeyGenParams",
		AESGcm:         "AesKeyGenParams",
		AESKw:          "AesKeyGenParams",
	},
}

// NormalizeAlgorithmName returns the normalized algorithm name.
//
// As the algorithm name is case-insensitive, we normalize it to
// our internal representation.
func NormalizeAlgorithmName(name string) AlgorithmIdentifier {
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

	return name
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

	return name
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
