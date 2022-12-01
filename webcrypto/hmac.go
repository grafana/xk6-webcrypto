package webcrypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"github.com/dop251/goja"
)

// HmacKeyAlgorithm represents the [HMAC key algorithm].
//
// [HMAC key algorithm]: https://www.w3.org/TR/WebCryptoAPI/#HmacKeyAlgorithm-dictionary
type HmacKeyAlgorithm struct {
	KeyAlgorithm

	// The inner hash function to use
	Hash KeyAlgorithm `json:"hash"`

	// The length (in bits) of the key.
	Length uint32 `json:"length"`
}

// HmacKeyGenParams represents the [HMAC key generation parameters].
//
// [HMAC key generation parameters]: https://www.w3.org/TR/WebCryptoAPI/#hmac-keygen-params
type HmacKeyGenParams struct {
	Algorithm

	// The inner hash function to use
	Hash HashAlgorithmIdentifier `json:"hash"`

	// The length (in bits) of the key to generate. If unspecified, the
	// recommended length will be used, which is the size of the associated
	// hash function.
	Length *uint32 `json:"length"`
}

// NewHmacKeyGenParams creates a new HmacKeyGenParams instance from a goja.Value.
//
//nolint:dupl
func NewHmacKeyGenParams(rt *goja.Runtime, v goja.Value) (HmacKeyGenParams, error) {
	if v == nil {
		return HmacKeyGenParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params HmacKeyGenParams
	if err := rt.ExportTo(v, &params); err != nil {
		return HmacKeyGenParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	// Because the hash field can either be a string or an object, we need to
	// handle it specifically.
	if hash, ok := v.ToObject(rt).Get("hash").Export().(string); ok {
		params.Hash = hash
	} else {
		var hash Algorithm
		if err := rt.ExportTo(v.ToObject(rt).Get("hash"), &hash); err != nil {
			return HmacKeyGenParams{}, NewError(0, SyntaxError, "hash algorithm is invalid")
		}
		params.Hash = hash.Name
	}

	if err := params.Validate(); err != nil {
		return HmacKeyGenParams{}, err
	}

	params.Normalize()

	return params, nil
}

// Ensure HmacKeyGenParams implements the Validator interface.
var _ Validator = HmacKeyGenParams{}

// Validate validates the HmacKeyGenParams instance fits the specifications
// requirements. It implements the Validator interface.
func (h HmacKeyGenParams) Validate() error {
	if h.Name == "" {
		return NewError(0, SyntaxError, "name property is required")
	}

	if !strings.EqualFold(h.Name, HMAC) {
		return NewError(0, NotSupportedError, "name property is invalid")
	}

	if h.Hash == "" {
		return NewError(0, SyntaxError, "hash property is required")
	}

	if !IsHashAlgorithm(h.Hash) {
		return NewError(0, NotSupportedError, "hash property is invalid")
	}

	if h.Length != nil && *h.Length == 0 {
		return NewError(0, SyntaxError, "length property must be greater than 0")
	}

	return nil
}

// Ensure HmacKeyGenParams implements the Normalizer interface.
var _ Normalizer = &HmacKeyGenParams{}

// Normalize normalizes the HmacKeyGenParams instance. It implements the
// Normalizer interface.
func (h *HmacKeyGenParams) Normalize() {
	h.Name = NormalizeAlgorithmName(h.Name)
	h.Hash = NormalizeHashAlgorithmName(h.Hash)
}

// Ensure HmacKeyGenParams implements the CryptoKeyGenerator interface.
var _ CryptoKeyGenerator[[]byte] = &HmacKeyGenParams{}

// GenerateKey generates a HMAC key.
//
// It implements the HMAC key generation operation of the Web Crypto [specification] 29.6.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#hmac
//
//nolint:funlen
func (h HmacKeyGenParams) GenerateKey(
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (*CryptoKey[[]byte], error) {
	if h.Algorithm.Name != "HMAC" {
		return nil, NewError(0, ImplementationError, "the algorithm is not HMAC")
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
	var length uint32
	if h.Length == nil {
		switch h.Hash {
		case Sha1:
			length = 512
		case Sha256:
			length = 512
		case Sha384:
			length = 1024
		case Sha512:
			length = 1024
		default:
			return nil, NewError(0, OperationError, "unsupported hash algorithm")
		}
	} else {
		length = *h.Length
	}

	// Generate a random corresponding to the
	// hash algorithm's block size.
	randomKey := make([]byte, length/8)
	if _, err := rand.Read(randomKey); err != nil {
		return nil, NewError(0, OperationError, err.Error())
	}

	// 3.
	hashFn, err := Hasher(h.Hash)
	if err != nil {
		return nil, NewError(0, OperationError, err.Error())
	}
	hmacHash := hmac.New(hashFn, randomKey)

	// 5.
	key := CryptoKey[[]byte]{
		Type:   SecretCryptoKeyType,
		handle: hmacHash.Sum(nil),
	}

	// 6. 7. 8. 9. 10.
	algorithm := HmacKeyAlgorithm{}
	algorithm.Name = NormalizeAlgorithmName(h.Name)
	hash := KeyAlgorithm{}
	hash.Name = NormalizeAlgorithmName(h.Hash)
	algorithm.Hash = hash
	algorithm.Length = length

	// 11.
	key.Algorithm = algorithm

	// 12.
	key.Extractable = extractable

	// 13.
	key.Usages = keyUsages

	// We apply the generateKey 8. step here, as we return a goja.Value
	// instead of a CryptoKey(Pair).
	if key.Usages == nil || len(key.Usages) == 0 {
		return nil, NewError(0, SyntaxError, "the keyUsages argument must contain at least one valid usage for the algorithm")
	}

	// 14.
	return &key, nil
}

// exportHMACKey exports a HMAC key in the given format.
// As defined in the [specification] for exporting HMAC keys
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#hmac-operations
func exportHMACKey(rt *goja.Runtime, format KeyFormat, key CryptoKey[[]byte]) (goja.Value, error) {
	// 1.
	if key.handle == nil {
		return nil, NewError(0, OperationError, "the key is not valid, no data")
	}

	// 2. 3.
	// TODO: verify that we comply with the spec here (octet string): https://www.w3.org/TR/WebCryptoAPI/#hmac-operations
	data := key.handle

	switch format {
	case RawKeyFormat:
		// 4.1.
		return rt.ToValue(rt.NewArrayBuffer(data)), nil
	case JwkKeyFormat:
		return exportHMACKeyAsJwk(rt, key)
	default:
		return nil, NewError(0, NotSupportedError, "unsupported key format")
	}
}

// exportHMACKeyAsJwk exports a HMAC key as a JWK object.
// As defined in the [specification] for exporting HMAC keys
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#hmac-operations
func exportHMACKeyAsJwk(rt *goja.Runtime, key CryptoKey[[]byte]) (goja.Value, error) {
	// 4.1.
	jwk := JSONWebKey{}

	// 4.2.
	jwk.KeyType = "oct"

	// 4.3.
	jwk.K = base64.URLEncoding.EncodeToString(key.handle)

	// 4.4.
	algorithm, ok := key.Algorithm.(HmacKeyAlgorithm)
	if !ok {
		return nil, NewError(0, ImplementationError, "unable to extract key's algorithm")
	}

	// 4.5.
	hash := algorithm.Hash

	// 4.6.
	switch hash.Name {
	case Sha1:
		jwk.Algorithm = "HS1"
	case Sha256:
		jwk.Algorithm = "HS256"
	case Sha384:
		jwk.Algorithm = "HS384"
	case Sha512:
		jwk.Algorithm = "HS512"
	default:
		return nil, NewError(0, OperationError, "unsupported hash algorithm")
	}

	// 4.7.
	jwk.KeyOps = make([]string, len(key.Usages))
	copy(jwk.KeyOps, key.Usages)

	// 4.8.
	jwk.Extractable = key.Extractable

	// 4.9.
	return rt.ToValue(jwk), nil
}
