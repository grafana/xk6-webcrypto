package webcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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

// NewEcKeyGenParams creates a new EcKeyGenParams instance from a goja.Value.
func NewEcKeyGenParams(rt *goja.Runtime, v goja.Value) (EcKeyGenParams, error) {
	if v == nil {
		return EcKeyGenParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params EcKeyGenParams
	if err := rt.ExportTo(v, &params); err != nil {
		return EcKeyGenParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	if err := params.Validate(); err != nil {
		return EcKeyGenParams{}, err
	}

	params.Normalize()

	return params, nil
}

// Ensure EcKeyGenParams implements the Validator interface.
var _ Validator = &EcKeyGenParams{}

// Validate validates the EcKeyGenParams instance. It implements the Validator
// interface.
func (e EcKeyGenParams) Validate() error {
	if e.Name == "" {
		return NewError(0, SyntaxError, "algorithm name is required")
	}

	if !strings.EqualFold(e.Name, ECDSA) {
		return NewError(0, SyntaxError, "invalid algorithm name")
	}

	if !IsEllipticCurve(string(e.NamedCurve)) {
		return NewError(0, NotSupportedError, "invalid elliptic curve name")
	}

	return nil
}

// Ensure EcKeyGenParams implements the Normalizer interface.
var _ Normalizer = &EcKeyGenParams{}

// Normalize normalizes the algorithm name and elliptic curve name. It implements the
// Normalizer interface.
func (e *EcKeyGenParams) Normalize() {
	e.Name = NormalizeAlgorithmName(e.Name)
	e.NamedCurve = EllipticCurveKind(strings.ToUpper(string(e.NamedCurve)))
}

// Ensure EcKeyGenParams implements the CryptoKeyPairGenerator interface.
var _ CryptoKeyPairGenerator[crypto.PrivateKey, crypto.PublicKey] = &EcKeyGenParams{}

// GenerateKeyPair generates a new Elliptic Curve key pair.
// It implements the CryptoKeyPairGenerator interface.
//
//nolint:funlen
func (e EcKeyGenParams) GenerateKeyPair(
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (*CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey], error) {
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
			continue
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
	publicKey.Usages = Intersection(
		keyUsages,
		InferCryptoKeyUsages(algorithm.Name, PublicCryptoKeyType),
	)
	publicKey.handle = privateKeyPair.Public()

	// 12. 13. 14. 15. 16.
	privateKey := CryptoKey[crypto.PrivateKey]{}
	privateKey.Type = PrivateCryptoKeyType
	privateKey.Algorithm = algorithm
	privateKey.Extractable = extractable
	privateKey.Usages = Intersection(
		keyUsages,
		InferCryptoKeyUsages(algorithm.Name, PrivateCryptoKeyType),
	)
	privateKey.handle = *privateKeyPair

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
	return &result, nil
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

// exportECKey exports the given Elliptic Curve key to the given format.
// As defined in the [specification]() for exporting ECDSA keys.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations
func exportECKey(rt *goja.Runtime, format KeyFormat, key goja.Value) (goja.Value, error) {
	// 3.
	switch format {
	case SpkiKeyFormat:
		return exportECKeyAsSpki(rt, key)
	case Pkcs8KeyFormat:
		return exportECKeyAsPkcs8(rt, key)
	case JwkKeyFormat:
		return exportECKeyAsJwk(rt, key)
	case RawKeyFormat:
		return exportECKeyAsRaw(rt, key)
	default:
		return nil, NewError(0, NotSupportedError, "unsupported key format")
	}
}

// exportECKeyAsSpki exports the given key as a SubjectPublicKeyInfo structure.
// As defined in the [specification] for exporting ECDSA keys.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations
func exportECKeyAsSpki(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	var cryptoKey CryptoKey[*ecdsa.PublicKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a public key")
	}

	// 2.
	if cryptoKey.handle == nil {
		return nil, NewError(0, OperationError, "key is not valid, no data")
	}

	// 3.1.
	if cryptoKey.Type != PublicCryptoKeyType {
		return nil, NewError(0, InvalidAccessError, "key is not a public key")
	}

	// 3.2.
	// FIXME: this is based on the assumption that this stdlib function does
	// the steps described in the specs. Verify and remove me.
	data, err := x509.MarshalPKIXPublicKey(cryptoKey.handle)
	if err != nil {
		return nil, NewError(0, OperationError, "failed to marshal public key")
	}

	// 3.3.
	return rt.ToValue(rt.NewArrayBuffer(data)), nil
}

// exportECKeyAsPkcs8 exports the given key as a PKCS#8 structure.
// As defined in the [specification] for exporting ECDSA keys.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations
func exportECKeyAsPkcs8(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	var cryptoKey CryptoKey[*ecdsa.PrivateKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	// 2.
	if cryptoKey.handle == nil {
		return nil, NewError(0, OperationError, "key is not valid, no data")
	}

	// 3.1.
	if cryptoKey.Type != PrivateCryptoKeyType {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	// TODO: verify that this actually complies with the specs (it should)
	data, err := x509.MarshalPKCS8PrivateKey(cryptoKey.handle)
	if err != nil {
		return nil, NewError(0, OperationError, "failed to marshal private key")
	}

	return rt.ToValue(rt.NewArrayBuffer(data)), nil
}

// exportECKeyAsJwk exports the given key as a JWK structure.
// As defined in the [specification] for exporting ECDSA keys.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations
func exportECKeyAsJwk(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// There's a trick here, as we need to handle both public and private keys
	// but we have a concrete type for them. Conviniently, Go exposes crypto
	// keys in a way that public key are contained by private keys, so we can
	// use this to our advantage.
	var cryptoKey CryptoKey[*ecdsa.PrivateKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	keyAlgorithm, ok := cryptoKey.Algorithm.(EcKeyAlgorithm)
	if !ok {
		return nil, NewError(0, ImplementationError, "unable to extract key data")
	}

	namedCurve := keyAlgorithm.NamedCurve

	// 2.1.
	jwk := JSONWebKey{}

	// 2.2.
	jwk.KeyType = "EC"

	// 3.
	if namedCurve == EllipticCurveKindP256 ||
		namedCurve == EllipticCurveKindP384 ||
		namedCurve == EllipticCurveKindP521 {
		// 3.1
		switch namedCurve {
		case EllipticCurveKindP256:
			jwk.Crv = "P-256"
		case EllipticCurveKindP384:
			jwk.Crv = "P-384"
		case EllipticCurveKindP521:
			jwk.Crv = "P-521"
		}

		// 3.2. 3.3.
		jwk.X = string(cryptoKey.handle.X.Bytes())
		jwk.Y = string(cryptoKey.handle.Y.Bytes())

		// 3.4.
		if cryptoKey.Type == PrivateCryptoKeyType {
			jwk.D = string(cryptoKey.handle.D.Bytes())
		}
	} else {
		// Otherwise 3.1
		// Note that in this implementation we do not support
		// "other applicable specifications", and thus error.
		return nil, NewError(0, NotSupportedError, "unsupported named curve")
	}

	// 4.
	jwk.KeyOps = make([]string, len(cryptoKey.Usages))
	copy(jwk.KeyOps, cryptoKey.Usages)

	// 5.
	jwk.Extractable = cryptoKey.Extractable

	return rt.ToValue(jwk), nil
}

// exportECKeyAsRaw exports the given key in raw format.
// As defined in the [specification] for exporting ECDSA keys.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations
func exportECKeyAsRaw(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// There's a trick here, as we need to handle both public and private keys
	// but we have a concrete type for them. Conviniently, Go exposes crypto
	// keys in a way that public key are contained by private keys, so we can
	// use this to our advantage.
	var cryptoKey CryptoKey[*ecdsa.PublicKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	keyAlgorithm, ok := cryptoKey.Algorithm.(EcKeyAlgorithm)
	if !ok {
		return nil, NewError(0, ImplementationError, "unable to extract key data")
	}

	// 2.
	var (
		isP256 = keyAlgorithm.NamedCurve == EllipticCurveKindP256
		isP384 = keyAlgorithm.NamedCurve == EllipticCurveKindP384
		isP521 = keyAlgorithm.NamedCurve == EllipticCurveKindP521
	)

	var data []byte
	if isP256 || isP384 || isP521 {
		data = elliptic.Marshal(cryptoKey.handle.Curve, cryptoKey.handle.X, cryptoKey.handle.Y)
	} else {
		// Otherwise 3.1
		// Note that in this implementation we do not support
		// "other applicable specifications", and thus error.
		return nil, NewError(0, NotSupportedError, "unsupported named curve")
	}

	// 3.
	return rt.ToValue(rt.NewArrayBuffer(data)), nil
}
