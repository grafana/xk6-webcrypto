package webcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"

	"github.com/dop251/goja"
)

// RsaKeyAlgorithm represents the [RSA key algorithm].
//
// [RSA key algorithm]: https://www.w3.org/TR/WebCryptoAPI/#RsaKeyAlgorithm-dictionary
type RsaKeyAlgorithm struct {
	KeyAlgorithm

	// ModulusLength contains the length, in bits, of the RSA modulus.
	ModulusLength uint32 `json:"modulusLength"`

	// PublicExponent contains the RSA public exponent value of the key to generate.
	PublicExponent []byte `json:"publicExponent"`
}

// RsaHashedKeyAlgorithm represents the [RSA algorithm for hashed keys].
//
// [RSA algorithm for hashed keys]: https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyAlgorithm-dictionary
type RsaHashedKeyAlgorithm struct {
	RsaKeyAlgorithm

	// Hash contains the hash algorithm that is used with this key.
	Hash KeyAlgorithm `json:"hash"`
}

// RsaKeyGenParams represents the [RSA key generation parameters].
//
// [RSA key generation parameters]: https://www.w3.org/TR/WebCryptoAPI/#RsaKeyGenParams-dictionary
type RsaKeyGenParams struct {
	Algorithm

	// ModulusLength contains the length, in bits, of the RSA modulus.
	ModulusLength uint32 `json:"modulusLength"`

	// PublicExponent contains the RSA public exponent value of the key to generate.
	PublicExponent []byte `json:"publicExponent"`
}

// RsaHashedKeyGenParams represents the RSA algorithm for hashed keys [key generation parameters].
//
// [key generation parameters]: https://www.w3.org/TR/WebCryptoAPI/#RsaHashedKeyGenParams-dictionary
type RsaHashedKeyGenParams struct {
	RsaKeyGenParams

	// Hash contains the hash algorithm to use.
	Hash HashAlgorithmIdentifier `json:"hash"`
}

// NewRsaHashedKeyGenParams creates a new RsaHashedKeyGenParams instance from a goja.Value.
//
//nolint:dupl
func NewRsaHashedKeyGenParams(rt *goja.Runtime, v goja.Value) (RsaHashedKeyGenParams, error) {
	if v == nil {
		return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params RsaHashedKeyGenParams
	if err := rt.ExportTo(v, &params); err != nil {
		return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	// Because the hash field can either be a string or an object, we need to
	// handle it specifically.
	if hash, ok := v.ToObject(rt).Get("hash").Export().(string); ok {
		params.Hash = hash
	} else {
		var hash Algorithm
		if err := rt.ExportTo(v.ToObject(rt).Get("hash"), &hash); err != nil {
			return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "hash algorithm is invalid")
		}
		params.Hash = hash.Name
	}

	if err := params.Validate(); err != nil {
		return RsaHashedKeyGenParams{}, err
	}

	params.Normalize()

	return params, nil
}

// Ensure RsaHashedKeyGenParams implements the Validator interface.
var _ Validator = &RsaHashedKeyGenParams{}

// Validate validates the RsaHashedKeyGenParams instance. It implements the
// Validator interface.
func (r RsaHashedKeyGenParams) Validate() error {
	if r.Name == "" {
		return NewError(0, SyntaxError, "name is required")
	}

	var (
		isRsaSsaPkcs1V15 = strings.EqualFold(r.Name, "RSASSA-PKCS1-v1_5")
		isRsaPss         = strings.EqualFold(r.Name, "RSA-PSS")
		isRsaOaep        = strings.EqualFold(r.Name, "RSA-OAEP")
	)

	if !isRsaSsaPkcs1V15 && !isRsaPss && !isRsaOaep {
		return NewError(0, NotSupportedError, "unsupported algorithm name")
	}

	if r.PublicExponent == nil {
		return NewError(0, OperationError, "publicExponent is required")
	}

	if len(r.PublicExponent) != 3 {
		return NewError(0, OperationError, "publicExponent must be 3 bytes")
	}

	if r.PublicExponent[0] != 0x01 || r.PublicExponent[1] != 0x00 || r.PublicExponent[2] != 0x01 {
		return NewError(0, OperationError, "publicExponent must be 0x010001")
	}

	if r.Hash == "" {
		return NewError(0, SyntaxError, "hash is required")
	}

	if !IsHashAlgorithm(r.Hash) {
		return NewError(0, NotSupportedError, "unsupported hash algorithm")
	}

	return nil
}

// Ensure RsaHashedKeyGenParams implements the Normalizer interface.
var _ Normalizer = &RsaHashedKeyGenParams{}

// Normalize normalizes the RsaHashedKeyGenParams instance. It implements
// the Normalizer interface.
func (r *RsaHashedKeyGenParams) Normalize() {
	r.Name = NormalizeAlgorithmName(r.Name)
	r.Hash = NormalizeHashAlgorithmName(r.Hash)
}

// Ensure RsaHashedKeyGenParams implements the CryptoKeyPairGenerator interface.
var _ CryptoKeyPairGenerator[crypto.PrivateKey, crypto.PublicKey] = &RsaHashedKeyGenParams{}

// GenerateKeyPair implements the CryptoKeyPairGenerator interface for RsaHashedKeyGenParams, and generates
// a new RSA key pair.
//
//nolint:funlen
func (r RsaHashedKeyGenParams) GenerateKeyPair(
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (*CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey], error) {
	var (
		isSSAPKCS1v15 = strings.EqualFold(r.Name, RSASsaPkcs1v15)
		isPSS         = strings.EqualFold(r.Name, RSAPss)
		isOAEP        = strings.EqualFold(r.Name, RSAOaep)
	)

	if !isSSAPKCS1v15 && !isPSS && !isOAEP {
		return nil, NewError(0, ImplementationError, "unsupported algorithm name")
	}

	// 1.
	for _, usage := range keyUsages {
		if strings.EqualFold(r.Name, RSAOaep) {
			switch usage {
			case EncryptCryptoKeyUsage, DecryptCryptoKeyUsage, WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage:
				continue
			default:
				return nil, NewError(0, SyntaxError, "invalid key usage")
			}
		} else {
			switch usage {
			case SignCryptoKeyUsage, VerifyCryptoKeyUsage:
				continue
			default:
				return nil, NewError(0, SyntaxError, "invalid key usage")
			}
		}
	}

	// 2.
	keyPair, err := rsa.GenerateKey(rand.Reader, int(r.ModulusLength))
	if err != nil {
		// 3.
		return nil, NewError(0, OperationError, "failed to generate RSA key pair")
	}

	// 4. 5. 6. 7. 8.
	algorithm := RsaHashedKeyAlgorithm{}
	algorithm.Name = NormalizeAlgorithmName(r.Name)
	algorithm.ModulusLength = r.ModulusLength
	algorithm.PublicExponent = r.PublicExponent
	algorithm.Hash = KeyAlgorithm{Name: r.Hash}

	// 9. 10. 11. 12. 13.
	publicKey := CryptoKey[crypto.PublicKey]{}
	publicKey.Type = PublicCryptoKeyType
	publicKey.Algorithm = algorithm
	publicKey.Extractable = true
	publicKey.Usages = Intersection(
		keyUsages,
		InferCryptoKeyUsages(algorithm.Name, PublicCryptoKeyType),
	)
	publicKey.handle = keyPair.Public()

	// 14. 15. 16. 17. 18.
	privateKey := CryptoKey[crypto.PrivateKey]{}
	privateKey.Type = PrivateCryptoKeyType
	privateKey.Algorithm = algorithm
	privateKey.Extractable = extractable
	privateKey.Usages = Intersection(
		keyUsages,
		InferCryptoKeyUsages(algorithm.Name, PrivateCryptoKeyType),
	)
	privateKey.handle = *keyPair

	// We apply the generateKey 8. step here, as we return a goja.Value
	// instead of a CryptoKey(Pair).
	if privateKey.Usages == nil || len(privateKey.Usages) == 0 {
		return nil, NewError(0, SyntaxError, "the keyUsages argument must contain at least one valid usage for the algorithm")
	}

	// 19. 20. 21.
	result := CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey]{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	// 22.
	return &result, nil
}

// exportRSAKey exports a RSA key to a given format.
// As defined in the ExportKey section of each RSA algorithm
// described in the [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#rsassa-pkcs1-operations
func exportRSAKey(rt *goja.Runtime, format KeyFormat, key goja.Value) (goja.Value, error) {
	switch format {
	case SpkiKeyFormat:
		return exportRSAKeyAsSpki(rt, key)
	case Pkcs8KeyFormat:
		return exportRSAKeyAsPkcs8(rt, key)
	case JwkKeyFormat:
		return exportRSAKeyAsJwk(rt, key)
	default:
		return nil, NewError(0, NotSupportedError, "unsupported key format")
	}
}

func exportRSAKeyAsSpki(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// 1.
	var cryptoKey CryptoKey[*rsa.PublicKey]
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
	// TODO: this is based on the assumption that this stdlib function does
	// the steps described in the specs. Verify and remove me.
	data, err := x509.MarshalPKIXPublicKey(cryptoKey.handle)
	if err != nil {
		return nil, NewError(0, OperationError, "failed to marshal public key")
	}

	return rt.ToValue(rt.NewArrayBuffer(data)), nil
}

func exportRSAKeyAsPkcs8(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// 1.
	var cryptoKey CryptoKey[*rsa.PrivateKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	// 2.
	if cryptoKey.handle == nil {
		return nil, NewError(0, OperationError, "key is not valid, no data")
	}

	// TODO: verify that this actually complies with the specs (it should)
	data, err := x509.MarshalPKCS8PrivateKey(cryptoKey.handle)
	if err != nil {
		return nil, NewError(0, OperationError, "failed to marshal private key")
	}

	return rt.ToValue(rt.NewArrayBuffer(data)), nil
}

//nolint:funlen
func exportRSAKeyAsJwk(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// There's a trick here, as we need to handle both public and private keys
	// but we have a concrete type for them. Conviniently, Go exposes crypto
	// keys in a way that public key are contained by private keys, so we can
	// use this to our advantage.
	var cryptoKey CryptoKey[*rsa.PrivateKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	keyAlgorithm, ok := cryptoKey.Algorithm.(RsaHashedKeyAlgorithm)
	if !ok {
		return nil, NewError(0, ImplementationError, "unable to extract key data")
	}

	// 2.1.
	jwk := JSONWebKey{}

	// 2.2.
	jwk.KeyType = "RSA"

	// 2.3.
	var prefix string
	switch keyAlgorithm.Name {
	case RSASsaPkcs1v15:
		prefix = "RS"
	case RSAPss:
		prefix = "PS"
	case RSAOaep:
		prefix = "RSA-OAEP-"
	default:
		return nil, NewError(0, NotSupportedError, "unsupported algorithm")
	}

	var suffix string
	switch keyAlgorithm.Hash.Name {
	case Sha1:
		if keyAlgorithm.Name == RSAOaep {
			suffix = ""
		} else {
			suffix = "1"
		}
	case Sha256:
		suffix = "256"
	case Sha384:
		suffix = "384"
	case Sha512:
		suffix = "512"
	default:
		return nil, NewError(0, NotSupportedError, "unsupported hash algorithm")
	}

	jwk.Algorithm = prefix + suffix

	// 3.4.
	// As defined in the JWA RFC: https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1
	jwk.N = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.N.Bytes())
	jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(cryptoKey.handle.E)).Bytes())

	// 3.5.
	// As defined in the JWA RFC: https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2
	if cryptoKey.Type == PrivateCryptoKeyType {
		jwk.D = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.D.Bytes())
		jwk.P = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Primes[0].Bytes())
		jwk.Q = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Primes[1].Bytes())
		jwk.Dp = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Precomputed.Dp.Bytes())
		jwk.Dq = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Precomputed.Dq.Bytes())
		jwk.Qi = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Precomputed.Qinv.Bytes())

		// 3.5.2.
		// TODO: "If the underlying RSA private key represented by
		// the [[handle]] internal slot of key is represented by more
		// than two primes, set the attribute named oth of jwk according
		// to the corresponding definition in JSON Web Algorithms, Section 6.3.2.7"
	}

	// 4.
	copy(jwk.KeyOps, cryptoKey.Usages)

	// 5.
	jwk.Extractable = cryptoKey.Extractable

	// 6.
	return rt.ToValue(jwk), nil
}
