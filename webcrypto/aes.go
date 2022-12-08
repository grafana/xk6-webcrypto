package webcrypto

import (
	"crypto/rand"
	"encoding/base64"
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

// AesKeyGenParams represents the object that should be passed as
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

			a.Name = name
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
func (a *AesKeyGenParams) GenerateKey(
	rt *goja.Runtime,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (goja.Value, error) {
	var (
		isCBC = a.Algorithm.Name == AESCbc
		isCTR = a.Algorithm.Name == AESCtr
		isGCM = a.Algorithm.Name == AESGcm
		isKW  = a.Algorithm.Name == AESKw
	)
	if !isCBC && !isCTR && !isGCM && !isKW {
		return nil, NewError(0, ImplementationError, "invalid algorithm")
	}

	// 1.
	for _, usage := range keyUsages {
		if strings.EqualFold(a.Algorithm.Name, AESKw) {
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
	if _, err := rand.Read(randomKey); err != nil {
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

// exportAESKey exports the given AES key to the given format.
// As defined in the [specification] for exporting AES keys.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#aes-ctr-operations
func exportAESKey(rt *goja.Runtime, format KeyFormat, key CryptoKey[[]byte]) (goja.Value, error) {
	if !key.Extractable {
		return nil, NewError(0, InvalidAccessError, "key is not extractable")
	}

	// 1.
	if key.handle == nil {
		return nil, NewError(0, OperationError, "key is not valid, no data")
	}

	// 2.
	switch format {
	case RawKeyFormat:
		return rt.ToValue(rt.NewArrayBuffer(key.handle)), nil
	case JwkKeyFormat:
		return exportAESKeyAsJwk(rt, key)
	default:
		return nil, NewError(0, NotSupportedError, "invalid key format")
	}
}

// exportAESKeyAsJwk exports the given AES key as a JWK key object.
// As defined in the [specification] for exporting AES keys.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#aes-ctr-operations
func exportAESKeyAsJwk(rt *goja.Runtime, key CryptoKey[[]byte]) (goja.Value, error) {
	// 2.1.
	jwk := JSONWebKey{}

	// 2.2.
	jwk.KeyType = "oct"

	// 2.3.
	jwk.K = base64.URLEncoding.EncodeToString(key.handle)

	// 2.4.
	aesAlgorithm, ok := key.Algorithm.(AesKeyAlgorithm)
	if !ok {
		return nil, NewError(0, ImplementationError, "unable to extract key algorithm")
	}
	var algorithmSuffix string
	switch aesAlgorithm.Name {
	case AESCbc:
		algorithmSuffix = "CBC"
	case AESCtr:
		algorithmSuffix = "CTR"
	case AESGcm:
		algorithmSuffix = "GCM"
	case AESKw:
		algorithmSuffix = "KW"
	}

	switch aesAlgorithm.Length {
	case 128:
		jwk.Algorithm = fmt.Sprintf("A128%s", algorithmSuffix)
	case 192:
		jwk.Algorithm = fmt.Sprintf("A192%s", algorithmSuffix)
	case 256:
		jwk.Algorithm = fmt.Sprintf("A256%s", algorithmSuffix)
	}

	// 2.5.
	jwk.KeyOps = make([]string, len(key.Usages))
	copy(jwk.KeyOps, key.Usages)

	// 2.6.
	jwk.Extractable = key.Extractable

	// 2.7.
	return rt.ToValue(jwk), nil
}
