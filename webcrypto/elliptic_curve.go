package webcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"

	"github.com/dop251/goja"
)

// EcKeyAlgorithm represents the Elliptic Curve key algorithm.
type EcKeyAlgorithm struct {
	KeyAlgorithm

	NamedCurve EllipticCurveKind `json:"namedCurve"`
}

// The ECDSAParams represents the object that should be passed as the algorithm
// parameter into `SubtleCrypto.Sign` or `SubtleCrypto.Verify“ when using the
// ECDSA algorithm.
//
// As defined in the [specification](https://www.w3.org/TR/WebCryptoAPI/#EcdsaParams-dictionary)
type ECDSAParams struct {
	// Name should be set to AlgorithmKindEcdsa.
	Name AlgorithmIdentifier `json:"name"`

	// Hash identifies the name of the digest algorithm to use.
	// You can use any of the following:
	//   * [Sha256]
	//   * [Sha384]
	//   * [Sha512]
	Hash AlgorithmIdentifier `json:"hash"`
}

// EcKeyGenParams  represents the object that should be passed as the algorithm
// parameter into `SubtleCrypto.GenerateKey`, when generating any
// elliptic-curve-based key pair: that is, when the algorithm is identified
// as either of AlgorithmKindEcdsa or AlgorithmKindEcdh.
//
// As defined in the [specification](https://www.w3.org/TR/WebCryptoAPI/#EcKeyGenParams-dictionary)
type EcKeyGenParams struct {
	// Algorithm holds the base algorithm description.
	// Its name should be set to either ECDSA or ECDH.
	Algorithm

	// NamedCurve holds (a String) the name of the curve to use.
	// You can use any of the following: CurveKindP256, CurveKindP384, or CurveKindP521.
	NamedCurve EllipticCurveKind `json:"namedCurve"`
}

// Ensure AesKeyGenParams implements the From interface.
var _ From[map[string]interface{}, EcKeyGenParams] = EcKeyGenParams{}

// From implements the From interface for EcKeyGenParams, and initializes the
// EcKeyGenParams instance from a map[string]interface{}.
func (e EcKeyGenParams) From(dict map[string]interface{}) (EcKeyGenParams, error) {
	var params EcKeyGenParams
	nameFound := false
	namedCurveFound := false

	for key, value := range dict {
		if strings.EqualFold(key, "name") {
			name, ok := value.(string)
			if !ok {
				return EcKeyGenParams{}, NewError(0, SyntaxError, "name property should hold a string")
			}

			name = strings.ToUpper(name)

			if !IsAlgorithm(name) {
				return EcKeyGenParams{}, NewError(0, NotSupportedError, "unsupported algorithm name")
			}

			params.Name = name
			nameFound = true
			continue
		}

		if strings.EqualFold(key, "namedCurve") {
			namedCurve, ok := value.(string)
			if !ok {
				return EcKeyGenParams{}, NewError(0, SyntaxError, "namedCurve property should hold a string")
			}

			namedCurve = strings.ToUpper(namedCurve)

			if !IsEllipticCurve(namedCurve) {
				return EcKeyGenParams{}, NewError(0, NotSupportedError, "unsupported elliptic curve name")
			}

			params.NamedCurve = EllipticCurveKind(namedCurve)
			namedCurveFound = true
			continue
		}
	}

	if !nameFound {
		return EcKeyGenParams{}, NewError(0, SyntaxError, "missing algorithm name")
	}

	if !namedCurveFound {
		return EcKeyGenParams{}, NewError(0, SyntaxError, "missing elliptic curve name")
	}

	return params, nil
}

// Ensure AesKeyGenParams implements the From interface.
var _ KeyGenerator = &EcKeyGenParams{}

// GenerateKey generates a new Elliptic Curve key pair.
//
//nolint:funlen
func (e *EcKeyGenParams) GenerateKey(
	rt *goja.Runtime,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (goja.Value, error) {
	if e.Algorithm.Name != ECDSA && e.Algorithm.Name != ECDH {
		return nil, NewError(0, ImplementationError, "invalid algorithm name")
	}

	// There are no implementation of the Diffie-Hellman key exchange algorithm
	// in the Go standard library, so we protect our users from ourselves (and themselves),
	// and refuse to generate ECDH keys until it is implement in the Go stdlib.
	//
	// As of November 2022, a proposal has been accepted, and ECDH implementation into
	// the golang standard library [is in progress].
	//
	// [is in progress]: https://github.com/golang/go/issues/52221
	if e.Algorithm.Name == ECDH {
		return nil, NewError(0, NotSupportedError, "ECDH key generation is not supported, yet")
	}

	// 1.
	for _, usage := range keyUsages {
		switch usage {
		case SignCryptoKeyUsage, VerifyCryptoKeyUsage:
		default:
			return nil, NewError(0, SyntaxError, "invalid key usage")
		}
	}

	// 2.
	// Check if the namedCurve is supported by the implementation.
	// Fetch the proper curve parameters.
	// Produce a random key pair using the curve parameters.
	if !IsEllipticCurve(string(e.NamedCurve)) {
		// 3.
		return nil, NewError(0, OperationError, "unsupported elliptic curve name")
	}

	var curve elliptic.Curve
	switch e.NamedCurve {
	case EllipticCurveKindP256:
		curve = elliptic.P256()
	case EllipticCurveKindP384:
		curve = elliptic.P384()
	case EllipticCurveKindP521:
		curve = elliptic.P521()
	}

	privateKeyPair, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		// 3.
		return nil, NewError(0, OperationError, "failed to generate key pair")
	}

	// 4. 5. 6.
	algorithm := EcKeyAlgorithm{
		KeyAlgorithm: KeyAlgorithm{
			Name: NormalizeAlgorithmName(e.Algorithm.Name),
		},
		NamedCurve: e.NamedCurve,
	}

	// 7. 8. 9. 10. 11.
	publicKey := CryptoKey[crypto.PublicKey]{}
	publicKey.Type = PublicCryptoKeyType
	publicKey.Algorithm = algorithm
	publicKey.Extractable = true
	publicKey.Usages = UsageIntersection(keyUsages, []CryptoKeyUsage{VerifyCryptoKeyUsage})
	publicKey.handle = privateKeyPair.Public()

	// 12. 13. 14. 15. 16.
	privateKey := CryptoKey[crypto.PrivateKey]{}
	privateKey.Type = PrivateCryptoKeyType
	privateKey.Algorithm = algorithm
	privateKey.Extractable = extractable
	privateKey.Usages = UsageIntersection(keyUsages, []CryptoKeyUsage{SignCryptoKeyUsage})
	privateKey.handle = privateKeyPair

	// We apply the generateKey 8. step here, as we return a goja.Value
	// instead of a CryptoKey(Pair).
	if privateKey.Usages == nil || len(privateKey.Usages) == 0 {
		return nil, NewError(0, SyntaxError, "the keyUsages argument must contain at least one valid usage for the algorithm")
	}

	// 17. 18. 19.
	result := CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey]{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	// 20.
	return rt.ToValue(result), nil
}

// EcKeyImportParams represents the object that should be passed as the algorithm parameter
// into `SubtleCrypto.ImportKey` or `SubtleCrypto.UnwrapKey`, when generating any elliptic-curve-based
// key pair: that is, when the algorithm is identified as either of ECDSA or ECDH.
type EcKeyImportParams struct {
	// Name should be set to AlgorithmKindEcdsa or AlgorithmKindEcdh.
	Name AlgorithmIdentifier `json:"name"`

	// NamedCurve holds (a String) the name of the elliptic curve to use.
	NamedCurve EllipticCurveKind `json:"namedCurve"`
}

// EllipticCurveKind represents the kind of elliptic curve that is being used.
type EllipticCurveKind string

const (
	// EllipticCurveKindP256 represents the P-256 curve.
	EllipticCurveKindP256 EllipticCurveKind = "P-256"

	// EllipticCurveKindP384 represents the P-384 curve.
	EllipticCurveKindP384 EllipticCurveKind = "P-384"

	// EllipticCurveKindP521 represents the P-521 curve.
	EllipticCurveKindP521 EllipticCurveKind = "P-521"
)

// IsEllipticCurve returns true if the given string is a valid EllipticCurveKind,
// false otherwise.
func IsEllipticCurve(name string) bool {
	switch name {
	case string(EllipticCurveKindP256):
		return true
	case string(EllipticCurveKindP384):
		return true
	case string(EllipticCurveKindP521):
		return true
	default:
		return false
	}
}
