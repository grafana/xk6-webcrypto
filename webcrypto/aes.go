package webcrypto

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/dop251/goja"
)

// AesKeyAlgorithm represents the AES algorithm.
type AesKeyAlgorithm struct {
	KeyAlgorithm

	// The length, in bits, of the key.
	Length int `json:"length"`
}

// AESKeyGenParams represents the object that should be passed as
// the algorithm parameter into `SubtleCrypto.generateKey`, when generating
// an AES key: that is, when the algorithm is identified as any
// of AES-CBC, AES-CTR, AES-GCM, or AES-KW.
type AesKeyGenParams struct {
	Algorithm

	// Length holds (a Number) the length of the key, in bits.
	Length int `json:"length"`
}

// Ensure AesKeyGenParams implements the From interface.
var _ From[map[string]interface{}, AesKeyGenParams] = AesKeyGenParams{}

// From fills the AesKeyGenParams from the given dictionary object.
func (a AesKeyGenParams) From(dict map[string]interface{}) (AesKeyGenParams, error) {
	nameFound := false
	lengthFound := false

	for key, value := range dict {
		if strings.EqualFold(key, "name") {
			name, ok := value.(string)
			if !ok {
				return AesKeyGenParams{}, NewError(0, SyntaxError, "name property should hold a string")
			}

			name = strings.ToUpper(name)

			if !IsAlgorithm(name) {
				return AesKeyGenParams{}, NewError(0, NotSupportedError, fmt.Sprintf("algorithm %s is not supported", name))
			}

			a.Name = AlgorithmIdentifier(name)
			nameFound = true
			continue
		}

		if strings.EqualFold(key, "length") {
			length, ok := value.(int64)
			if !ok {
				return AesKeyGenParams{}, NewError(0, SyntaxError, "length property should hold a number")
			}

			a.Length = int(length)
			lengthFound = true
			continue
		}
	}

	if !nameFound {
		return AesKeyGenParams{}, NewError(0, SyntaxError, "name property is required")
	}

	if !lengthFound {
		return AesKeyGenParams{}, NewError(0, SyntaxError, "length property is required")
	}

	return a, nil
}

// Ensure AesKeyGenParams implements the From interface.
var _ KeyGenerator = &AesKeyGenParams{}

// GenerateKey generates a new AES key.
func (a *AesKeyGenParams) GenerateKey(rt *goja.Runtime, extractable bool, keyUsages []CryptoKeyUsage) (goja.Value, error) {
	if a.Algorithm.Name != AESCbc && a.Algorithm.Name != AESCtr && a.Algorithm.Name != AESGcm && a.Algorithm.Name != AESKw {
		return nil, NewError(0, ImplementationError, "invalid algorithm")
	}

	// 1.
	for _, usage := range keyUsages {
		if strings.EqualFold(string(a.Algorithm.Name), AESKw) {
			switch usage {
			case WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage:
			default:
				return nil, NewError(0, SyntaxError, "invalid key usage")
			}
		} else {
			switch usage {
			case EncryptCryptoKeyUsage, DecryptCryptoKeyUsage, WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage:
			default:
				return nil, NewError(0, SyntaxError, "invalid key usage")
			}
		}
	}

	// 2.
	if a.Length != int(KeyLength128) && a.Length != int(KeyLength192) && a.Length != int(KeyLength256) {
		return nil, NewError(0, OperationError, "invalid key length")
	}

	// 3.
	// FIXME: verify if there are different constraints on the key format depending on the AES flavor
	randomKey := make([]byte, a.Length/8)
	_, err := rand.Read(randomKey)
	if err != nil {
		// 4.
		return nil, NewError(0, OperationError, "could not generate random key")
	}

	// 5. 6. 7. 8. 9.
	key := CryptoKey[[]byte]{}
	key.Type = SecretCryptoKeyType
	key.Algorithm = AesKeyAlgorithm{
		KeyAlgorithm: KeyAlgorithm{
			Name: a.Name,
		},
		Length: a.Length,
	}

	// 10.
	key.Extractable = extractable

	// 11.
	key.Usages = keyUsages

	// Set key handle to our random key.
	key.handle = randomKey

	// We apply the generateKey 8. step here, as we return a goja.Value
	// instead of a CryptoKey(Pair).
	if key.Usages == nil || len(key.Usages) == 0 {
		return nil, NewError(0, SyntaxError, "the keyUsages argument must contain at least one valid usage for the algorithm")
	}

	// 12.
	return rt.ToValue(key), nil
}
