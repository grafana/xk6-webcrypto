package webcrypto

import (
	"crypto/hmac"
	"crypto/rand"
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
//nolint:ifshort
func (h HmacKeyGenParams) From(dict map[string]interface{}) (HmacKeyGenParams, error) {
	params := HmacKeyGenParams{}
	nameFound := false
	hashFound := false

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
