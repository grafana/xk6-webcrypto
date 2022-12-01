package webcrypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
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
	// FIXME: we derive from the specs here by accepting only a string, and not
	// an object as algorithm for HMAC.hash for instance
	Hash HashAlgorithmIdentifier `json:"hash"`

	// The length (in bits) of the key to generate. If unspecified, the
	// recommended length will be used, which is the size of the associated
	// hash function.
	Length *uint32 `json:"length"`
}

// Ensure AesKeyGenParams implements the From interface.
var _ From[map[string]interface{}, HmacKeyGenParams] = HmacKeyGenParams{}

// From implements the From interface for HmacKeyGenParams, and initializes the
// instance from a map[string]interface{}.
//
// FIXME: this is the exact same code as HmacImportParams.From
//
//nolint:dupl
func (h HmacKeyGenParams) From(dict map[string]interface{}) (HmacKeyGenParams, error) {
	params := HmacKeyGenParams{}
	var nameFound bool
	var hashFound bool

	for key, value := range dict {
		if strings.EqualFold(key, "name") {
			name, ok := value.(string)
			if !ok {
				return HmacKeyGenParams{}, NewError(0, SyntaxError, fmt.Sprintf("the %s property must be a string", key))
			}

			name = strings.ToUpper(name)

			if !IsAlgorithm(name) {
				err := NewError(0, NotSupportedError, fmt.Sprintf("the %s property is not a supported algorithm", key))
				return HmacKeyGenParams{}, err
			}

			params.Name = name
			nameFound = true
			continue
		}

		if strings.EqualFold(key, "hash") {
			switch t := dict[key].(type) {
			case string:
				t = strings.ToUpper(t)

				if !IsHashAlgorithm(t) {
					return HmacKeyGenParams{}, NewError(0, "NotSupportedError", fmt.Sprintf("Unsupported hash algorithm  %s", t))
				}

				params.Hash = t
				hashFound = true
			case map[string]interface{}:
				alg, err := Algorithm{}.From(t)
				if err != nil {
					return HmacKeyGenParams{}, err
				}

				params.Hash = alg.Name
				hashFound = true
			}

			continue
		}

		if strings.EqualFold(key, "length") {
			length, ok := value.(int64)
			if !ok {
				return HmacKeyGenParams{}, NewError(0, SyntaxError, fmt.Sprintf("the %s property must be a number", key))
			}

			ulength := uint32(length)
			params.Length = &ulength
			continue
		}
	}

	if !nameFound {
		return HmacKeyGenParams{}, NewError(0, SyntaxError, "the name property is missing")
	}

	if !hashFound {
		return HmacKeyGenParams{}, NewError(0, SyntaxError, "the hash property is missing")
	}

	return params, nil
}

// Ensure AesKeyGenParams implements the From interface.
var _ KeyGenerator = &HmacKeyGenParams{}

// GenerateKey generates a HMAC key.
//
// It implements the HMAC key generation operation of the Web Crypto [specification] 29.6.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#hmac
//
//nolint:funlen
func (h *HmacKeyGenParams) GenerateKey(
	rt *goja.Runtime,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (goja.Value, error) {
	if h.Algorithm.Name != "HMAC" {
		return nil, NewError(0, ImplementationError, "the algorithm is not HMAC")
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
	return rt.ToValue(key), nil
}

// HmacImportParams represents the HMAC key algorithm parameters
// used to import a HMAC key.
type HmacImportParams struct {
	Algorithm

	// The inner hash function to use.
	Hash string `json:"hash"`

	// The length of the key in bits.
	Length *uint32 `json:"length"`
}

// Ensure HmacImportParams implements the From interface.
var _ From[map[string]interface{}, HmacImportParams] = HmacImportParams{}

// From creates a new HmacImportParams from the given dictionary.
//
// FIXME: this is the exact same code as HmacKeyGenParams.From.
//
//nolint:dupl
func (h HmacImportParams) From(dict map[string]interface{}) (HmacImportParams, error) {
	params := HmacImportParams{}
	nameFound := false
	hashFound := false //nolint:ifshort

	for key, value := range dict {
		if strings.EqualFold(key, "name") {
			name, ok := value.(string)
			if !ok {
				return HmacImportParams{}, NewError(0, SyntaxError, fmt.Sprintf("the %s property must be a string", key))
			}

			name = strings.ToUpper(name)

			if !IsAlgorithm(name) {
				err := NewError(0, NotSupportedError, fmt.Sprintf("the %s property is not a supported algorithm", key))
				return HmacImportParams{}, err
			}

			params.Name = name
			nameFound = true
			continue
		}

		if strings.EqualFold(key, "hash") {
			switch t := dict[key].(type) {
			case string:
				t = strings.ToUpper(t)

				if !IsHashAlgorithm(t) {
					return HmacImportParams{}, NewError(0, "NotSupportedError", fmt.Sprintf("Unsupported hash algorithm  %s", t))
				}

				params.Hash = t
				hashFound = true
			case map[string]interface{}:
				alg, err := Algorithm{}.From(t)
				if err != nil {
					return HmacImportParams{}, err
				}

				params.Hash = alg.Name
				hashFound = true
			}

			continue
		}

		if strings.EqualFold(key, "length") {
			length, ok := value.(int64)
			if !ok {
				return HmacImportParams{}, NewError(0, SyntaxError, fmt.Sprintf("the %s property must be a number", key))
			}

			ulength := uint32(length)
			params.Length = &ulength
			continue
		}
	}

	if !nameFound {
		return HmacImportParams{}, NewError(0, SyntaxError, "the name property is missing")
	}

	if !hashFound {
		return HmacImportParams{}, NewError(0, SyntaxError, "the hash property is missing")
	}

	return params, nil
}

// importHMACKey imports a HMAC key from the given key data and turns it
// into a CryptoKey.
//
// TODO: Note that AES-KW is not supported as of yet.
func importHMACKey(
	rt *goja.Runtime,
	normalizedAlgorithm HmacImportParams,
	keyData goja.Value,
	format KeyFormat,
	extractable bool,
	usages []CryptoKeyUsage,
) (CryptoKey[[]byte], error) {
	// 2.
	if !ContainsOnly(usages, SignCryptoKeyUsage, VerifyCryptoKeyUsage) {
		return CryptoKey[[]byte]{}, NewError(0, SyntaxError, "invalid key usage")
	}

	// 3.
	hash := KeyAlgorithm{}

	// 4.
	var data []byte
	var err error

	switch format {
	case RawKeyFormat:
		// 4.1. 4.2.
		data, err = importHMACKeyFromRaw(rt, keyData, normalizedAlgorithm, &hash)
		if err != nil {
			return CryptoKey[[]byte]{}, err
		}
	case JwkKeyFormat:
		// 4.1. 4.2.
		data, err = importHMACKeyFromJwk(rt, keyData, extractable, usages, normalizedAlgorithm, &hash)
		if err != nil {
			return CryptoKey[[]byte]{}, err
		}
	default:
		return CryptoKey[[]byte]{}, NewError(0, NotSupportedError, "unsupported key format")
	}

	// 5.
	length := uint32(len(data) * 8)

	// 6.
	if length == 0 {
		return CryptoKey[[]byte]{}, NewError(0, DataError, "the key data is empty")
	}

	// 7.
	switch nl := normalizedAlgorithm.Length; {
	case nl != nil && *nl > length:
		return CryptoKey[[]byte]{}, NewError(0, DataError, "the key data length and import params' do not match")
	case nl != nil && *nl <= length-8:
		return CryptoKey[[]byte]{}, NewError(0, DataError, "the key data length and import params' do not match")
	default:
		length = *normalizedAlgorithm.Length
	}

	// 8.
	key := CryptoKey[[]byte]{
		handle: data[:length/8],
	}

	// 9.
	algorithm := HmacKeyAlgorithm{}

	// 10.
	algorithm.Name = HMAC

	// 11.
	algorithm.Length = length

	// 12.
	algorithm.Hash = hash

	// 13.
	key.Algorithm = algorithm

	return key, nil
}

func importHMACKeyFromRaw(
	rt *goja.Runtime,
	keyData goja.Value,
	normalizedAlgorithm HmacImportParams,
	hash *KeyAlgorithm,
) ([]byte, error) {
	var data []byte

	// 4.1.
	err := rt.ExportTo(keyData, &data)
	if err != nil {
		return nil, NewError(0, DataError, "invalid key data")
	}

	// 4.2.
	hash.Name = normalizedAlgorithm.Hash

	return data, nil
}

//nolint:gocognit,cyclop
func importHMACKeyFromJwk(
	rt *goja.Runtime,
	keyData goja.Value,
	extractable bool,
	usages []CryptoKeyUsage,
	normalizedAlgorithm HmacImportParams,
	hash *KeyAlgorithm,
) ([]byte, error) {
	var data []byte

	// 2.1.
	var jwk JSONWebKey
	err := rt.ExportTo(keyData, &jwk)
	if err != nil {
		return nil, NewError(0, DataError, "could not import data as JSON Web Key")
	}

	// 2.2.
	if jwk.KeyType != "oct" {
		return nil, NewError(0, DataError, "invalid key type")
	}

	// 2.3.
	if jwk.K == "" || jwk.Algorithm == "" {
		return nil, NewError(0, DataError, "invalid key data")
	}

	// 2.4.
	data, err = base64.URLEncoding.DecodeString(jwk.K)
	if err != nil {
		return nil, NewError(0, DataError, "invalid decoded key data")
	}

	// 2.5.
	hash.Name = normalizedAlgorithm.Name

	// 2.6.
	switch hash.Name {
	case Sha1:
		if jwk.Algorithm != "" && jwk.Algorithm != "HS1" {
			return nil, NewError(0, DataError, "invalid algorithm")
		}
	case Sha256:
		if jwk.Algorithm != "" && jwk.Algorithm != "HS256" {
			return nil, NewError(0, DataError, "invalid algorithm")
		}
	case Sha384:
		if jwk.Algorithm != "" && jwk.Algorithm != "HS384" {
			return nil, NewError(0, DataError, "invalid algorithm")
		}
	case Sha512:
		if jwk.Algorithm != "" && jwk.Algorithm != "HS512" {
			return nil, NewError(0, DataError, "invalid algorithm")
		}
	default:
		return nil, NewError(0, DataError, "invalid algorithm")
	}

	// 2.7.
	if len(usages) != 0 && jwk.Use != "" && jwk.Use != "sign" {
		return nil, NewError(0, DataError, "invalid key usage")
	}

	// 2.8.
	if jwk.KeyOps != nil {
		for _, usage := range usages {
			if !Contains(jwk.KeyOps, usage) {
				return nil, NewError(0, DataError, "invalid key usage")
			}
		}
	}

	if !jwk.Extractable && extractable {
		return nil, NewError(0, DataError, "invalid key extractability")
	}

	return data, nil
}
