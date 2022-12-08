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

// importAES imports an AES key from the given key data and turns it
// into a CryptoKey.
// The key data must be a base64 encoded string. The key data
// must be a valid AES key.
//
// TODO: Note that AES-KW is not supported as of yet.
func importAESKey(
	rt *goja.Runtime,
	algorithmName AlgorithmIdentifier,
	keyData goja.Value,
	format KeyFormat,
	extractable bool,
	usages []CryptoKeyUsage,
) (CryptoKey[[]byte], error) {
	// 1.
	if !ContainsOnly(
		usages,
		EncryptCryptoKeyUsage,
		DecryptCryptoKeyUsage,
		WrapKeyCryptoKeyUsage,
		UnwrapKeyCryptoKeyUsage) {
		return CryptoKey[[]byte]{}, NewError(0, SyntaxError, "invalid key usage")
	}

	// 2.
	var data []byte
	var err error

	switch format {
	case RawKeyFormat:
		data, err = importAESKeyFromRaw(rt, keyData)
		if err != nil {
			return CryptoKey[[]byte]{}, err
		}
	case JwkKeyFormat:
		data, err = importAESKeyFromJwk(rt, algorithmName, keyData, extractable, usages)
		if err != nil {
			return CryptoKey[[]byte]{}, err
		}
	default:
		return CryptoKey[[]byte]{}, NewError(0, NotSupportedError, "unsupported key format")
	}

	// 3.
	key := CryptoKey[[]byte]{
		Type:   SecretCryptoKeyType,
		handle: data,
	}

	// 4.
	algorithm := AesKeyAlgorithm{}

	// 5.
	algorithm.Name = algorithmName

	// 6.
	algorithm.Length = int(KeyLength(len(data) * 8)) // length is in bits

	// 7.
	key.Algorithm = algorithm

	// 8.
	return key, nil
}

func importAESKeyFromRaw(rt *goja.Runtime, keyData goja.Value) ([]byte, error) {
	var data []byte

	// 2.1.
	err := rt.ExportTo(keyData, &data)
	if err != nil {
		return nil, NewError(0, DataError, "could not export key data")
	}

	// 2.2.
	var (
		has128Bits = len(data) == 16
		has192Bits = len(data) == 24
		has256Bits = len(data) == 32
	)

	if !has128Bits && !has192Bits && has256Bits {
		return nil, NewError(0, DataError, "invalid key length")
	}

	return data, nil
}

// importAESKeyAsJwk imports an AES key from the given JWK key data and
// returns a CryptoKey handle bytes.
//
//nolint:funlen,gocognit,cyclop
func importAESKeyFromJwk(
	rt *goja.Runtime,
	algorithmName AlgorithmIdentifier,
	keyData goja.Value,
	extractable bool,
	usages []CryptoKeyUsage,
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
	var suffix string

	switch algorithmName {
	case AESCbc:
		suffix = "CBC"
	case AESCtr:
		suffix = "CTR"
	case AESGcm:
		suffix = "GCM"
	default:
		return nil, NewError(0, DataError, "invalid algorithm")
	}

	switch len(data) {
	case 16: // 128 bits
		if jwk.Algorithm != "" && jwk.Algorithm != "A128"+suffix {
			return nil, NewError(0, DataError, "invalid algorithm")
		}
	case 24: // 192 bits
		if jwk.Algorithm != "" && jwk.Algorithm != "A192"+suffix {
			return nil, NewError(0, DataError, "invalid algorithm")
		}
	case 32: // 256 bits
		if jwk.Algorithm != "" && jwk.Algorithm != "A256"+suffix {
			return nil, NewError(0, DataError, "invalid algorithm")
		}
	default:
		return nil, NewError(0, DataError, "invalid key length")
	}

	// 2.6.
	if len(usages) != 0 && jwk.Use != "" && jwk.Use != "enc" {
		return nil, NewError(0, DataError, "invalid key usage")
	}

	// 2.7.
	if jwk.KeyOps != nil {
		for _, usage := range usages {
			if !Contains(jwk.KeyOps, usage) {
				return nil, NewError(0, DataError, "invalid key usage")
			}
		}
	}

	// 2.8.
	if !jwk.Extractable && extractable {
		return nil, NewError(0, DataError, "invalid key extractability")
	}

	return data, nil
}
