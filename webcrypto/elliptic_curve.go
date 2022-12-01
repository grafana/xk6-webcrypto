package webcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"

	"github.com/dop251/goja"
)

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
//
// FIXME: this is a duplicate of EcKeyImportParams.From, and should be refactored.
//
//nolint:dupl
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

// Ensure EcKeyImportParams implements the From interface.
var _ From[map[string]interface{}, EcKeyImportParams] = EcKeyImportParams{}

// From implements the From interface for EcKeyImportParams, and initializes the
// EcKeyImportParams instance from a map[string]interface{}.
//
// FIXME: this is a duplicate of EcKeyGenParams.From, and should be refactored.
//
//nolint:dupl
func (e EcKeyImportParams) From(dict map[string]interface{}) (EcKeyImportParams, error) {
	var params EcKeyImportParams
	nameFound := false
	namedCurveFound := false

	for key, value := range dict {
		if strings.EqualFold(key, "name") {
			name, ok := value.(string)
			if !ok {
				return EcKeyImportParams{}, NewError(0, SyntaxError, "name property should hold a string")
			}

			name = strings.ToUpper(name)

			if !IsAlgorithm(name) {
				return EcKeyImportParams{}, NewError(0, NotSupportedError, "unsupported algorithm name")
			}

			params.Name = name
			nameFound = true
			continue
		}

		if strings.EqualFold(key, "namedCurve") {
			namedCurve, ok := value.(string)
			if !ok {
				return EcKeyImportParams{}, NewError(0, SyntaxError, "namedCurve property should hold a string")
			}

			namedCurve = strings.ToUpper(namedCurve)

			if !IsEllipticCurve(namedCurve) {
				return EcKeyImportParams{}, NewError(0, NotSupportedError, "unsupported elliptic curve name")
			}

			params.NamedCurve = EllipticCurveKind(namedCurve)
			namedCurveFound = true
			continue
		}
	}

	if !nameFound {
		return EcKeyImportParams{}, NewError(0, SyntaxError, "missing algorithm name")
	}

	if !namedCurveFound {
		return EcKeyImportParams{}, NewError(0, SyntaxError, "missing elliptic curve name")
	}

	return params, nil
}

func importECKey(
	rt *goja.Runtime,
	format KeyFormat,
	key goja.Value,
	extractable bool,
	usages []CryptoKeyUsage,
	normalizedAlgorithm EcKeyImportParams,
) (goja.Value, error) {
	var result goja.Value
	var err error
	// 2.
	switch format {
	case SpkiKeyFormat:
		result, err = importEcKeyFromSpki(rt, key, usages, normalizedAlgorithm)
		if err != nil {
			return nil, err
		}
	case Pkcs8KeyFormat:
		result, err = importEcKeyFromPkcs8(rt, key, usages, normalizedAlgorithm)
		if err != nil {
			return nil, err
		}
	case JwkKeyFormat:
		result, err = importEcKeyFromJwk(rt, key, extractable, usages, normalizedAlgorithm)
		if err != nil {
			return nil, err
		}
	case RawKeyFormat:
		return nil, NewError(0, NotSupportedError, "raw key format not supported for EC keys")
	default:
	}

	// 3.
	return result, nil
}

//nolint:dupl
func importEcKeyFromSpki(
	rt *goja.Runtime,
	keyData goja.Value,
	usages []CryptoKeyUsage,
	normalizedAlgorithm EcKeyImportParams,
) (goja.Value, error) {
	// 1.
	var data []byte
	err := rt.ExportTo(keyData, &data)
	if err != nil {
		return nil, NewError(0, DataError, "could not export key data")
	}

	// 2.1.
	if !ContainsOnly(usages, VerifyCryptoKeyUsage) {
		return nil, NewError(0, SyntaxError, "invalid key usage")
	}

	// 2.2.
	k, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, NewError(0, DataError, "could not parse key data")
	}

	ecKey, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, NewError(0, DataError, "could not parse key data")
	}

	// 2.3. 2.4. 2.5. 2.6. 2.7. we assume are handled by the crypto/x509 package.

	// 2.8.
	var namedCurve EllipticCurveKind

	// 2.9.
	switch ecKey.Curve.Params().Name {
	case "P-256":
		namedCurve = EllipticCurveKindP256
	case "P-384":
		namedCurve = EllipticCurveKindP384
	case "P-521":
		namedCurve = EllipticCurveKindP521
	default:
		// 2.10.
		return nil, NewError(0, DataError, "unsupported elliptic curve")
	}

	// 2.10.
	key := CryptoKey[*ecdsa.PublicKey]{
		handle: ecKey,
	}

	// 2.11.
	if namedCurve != "" && namedCurve != normalizedAlgorithm.NamedCurve {
		return nil, NewError(0, DataError, "unsupported elliptic curve")
	}

	// 2.12. we don't need to check that our public key uses the appropriate
	// elliptic curve.

	// 2.13.
	key.Type = PublicCryptoKeyType

	// 2.14.
	algorithm := EcKeyAlgorithm{}

	// 2.15.
	algorithm.Name = ECDSA

	// 2.16.
	algorithm.NamedCurve = namedCurve

	// 2.17.
	key.Algorithm = algorithm

	return rt.ToValue(key), nil
}

//nolint:dupl
func importEcKeyFromPkcs8(
	rt *goja.Runtime,
	keyData goja.Value,
	usages []CryptoKeyUsage,
	normalizedAlgorithm EcKeyImportParams,
) (goja.Value, error) {
	// 1.
	var data []byte
	err := rt.ExportTo(keyData, &data)
	if err != nil {
		return nil, NewError(0, DataError, "could not export key data")
	}

	// 2.1.
	if !ContainsOnly(usages, SignCryptoKeyUsage) {
		return nil, NewError(0, SyntaxError, "invalid key usage")
	}

	// 2.2.
	k, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		// 2.3.
		return nil, NewError(0, DataError, "could not parse key data")
	}

	ecPrivateKey, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		// 2.3.
		return nil, NewError(0, DataError, "could not parse key data")
	}

	// 2.4. 2.5. 2.6. 2.7. we assume are handled by the crypto/x509 package.

	// 2.8.
	var namedCurve EllipticCurveKind

	// 2.9.
	switch ecPrivateKey.Curve.Params().Name {
	case "P-256":
		namedCurve = EllipticCurveKindP256
	case "P-384":
		namedCurve = EllipticCurveKindP384
	case "P-521":
		namedCurve = EllipticCurveKindP521
	default:
		// 2.10.
		return nil, NewError(0, DataError, "unsupported elliptic curve")
	}

	// 2.10.
	key := CryptoKey[*ecdsa.PrivateKey]{
		handle: ecPrivateKey,
	}

	// 2.11.
	if namedCurve != "" && namedCurve != normalizedAlgorithm.NamedCurve {
		return nil, NewError(0, DataError, "unsupported elliptic curve")
	}

	// 2.12. we don't need to check that our public key uses the appropriate
	// elliptic curve.

	// 2.13.
	key.Type = PublicCryptoKeyType

	// 2.14.
	algorithm := EcKeyAlgorithm{}

	// 2.15.
	algorithm.Name = ECDSA

	// 2.16.
	algorithm.NamedCurve = namedCurve

	// 2.17.
	key.Algorithm = algorithm

	return rt.ToValue(key), nil
}

//nolint:funlen,gocognit,cyclop
func importEcKeyFromJwk(
	rt *goja.Runtime,
	keyData goja.Value,
	extractable bool,
	usages []CryptoKeyUsage,
	normalizedAlgorithm EcKeyImportParams,
) (goja.Value, error) {
	// 2.1.
	var jwk JSONWebKey
	err := rt.ExportTo(keyData, &jwk)
	if err != nil {
		return nil, NewError(0, DataError, "could not import data as JSON Web Key")
	}

	// 2.2.
	if jwk.D != "" && jwk.D != SignCryptoKeyUsage || jwk.D == "" && !Contains(usages, VerifyCryptoKeyUsage) {
		return nil, NewError(0, DataError, "invalid key usage")
	}

	// 2.3.
	if jwk.KeyType != "EC" {
		return nil, NewError(0, DataError, "invalid key type")
	}

	// 2.4.
	if usages != nil && jwk.Use != "" && jwk.Use != "sig" {
		return nil, NewError(0, DataError, "invalid key usage")
	}

	// 2.5.
	if jwk.KeyOps != nil {
		for _, usage := range usages {
			if !Contains(jwk.KeyOps, usage) {
				return nil, NewError(0, DataError, "invalid key usage")
			}
		}
	}

	// 2.6.
	if !jwk.Extractable && extractable {
		return nil, NewError(0, DataError, "invalid key extractability")
	}

	// 2.7.
	namedCurve := jwk.Crv

	// 2.8.
	if namedCurve != string(normalizedAlgorithm.NamedCurve) {
		return nil, NewError(0, DataError, "invalid key curve")
	}

	// 2.8.1.
	var algNamedCurve EllipticCurveKind

	// 2.8.2.
	switch jwk.Algorithm {
	case string(EllipticCurveKindP256):
		algNamedCurve = EllipticCurveKindP256
	case string(EllipticCurveKindP384):
		algNamedCurve = EllipticCurveKindP384
	case string(EllipticCurveKindP521):
		algNamedCurve = EllipticCurveKindP521
	default:
		break
	}

	// 2.8.3.
	if algNamedCurve != "" && algNamedCurve != normalizedAlgorithm.NamedCurve {
		return nil, NewError(0, DataError, "algorithm does not match key curve")
	}

	// 2.11. 2.12. 2.13. We do these before hand to avoid repetition
	// in the code below.
	algorithm := EcKeyAlgorithm{}
	algorithm.Name = ECDSA
	algorithm.NamedCurve = EllipticCurveKind(namedCurve)

	// 2.8.4.
	// FIXME: this should check if D is present (as in an optional not set, rather than empty string)
	if jwk.D != "" {
		// 2.8.4.1.
		keyData, err := base64.URLEncoding.DecodeString(jwk.D)
		if err != nil {
			return nil, NewError(0, DataError, "could not decode key data")
		}

		// 2.8.4.2.
		ecPrivateKey := &ecdsa.PrivateKey{
			D: new(big.Int).SetBytes(keyData),
		}

		public := ecPrivateKey.Public()
		ecPrivateKey.PublicKey = *public.(*ecdsa.PublicKey) //nolint:forcetypeassert

		key := CryptoKey[*ecdsa.PrivateKey]{
			Algorithm: algorithm,
			handle:    ecPrivateKey,
		}

		// 2.8.4.3.
		key.Type = PrivateCryptoKeyType

		return rt.ToValue(key), nil
	}

	if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
		return nil, NewError(0, DataError, "could not parse key data")
	}

	var ec elliptic.Curve
	switch jwk.Crv {
	case string(EllipticCurveKindP256):
		ec = elliptic.P256()
	case string(EllipticCurveKindP384):
		ec = elliptic.P384()
	case string(EllipticCurveKindP521):
		ec = elliptic.P521()
	default:
		return nil, NewError(0, DataError, "could not parse key data")
	}

	ecPublicKey := &ecdsa.PublicKey{
		Curve: ec,
		X:     new(big.Int).SetBytes([]byte(jwk.X)),
		Y:     new(big.Int).SetBytes([]byte(jwk.Y)),
	}

	return rt.ToValue(CryptoKey[*ecdsa.PublicKey]{
		Algorithm: algorithm,
		Type:      PublicCryptoKeyType,
		handle:    ecPublicKey,
	}), nil
}

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
