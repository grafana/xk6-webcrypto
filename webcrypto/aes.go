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

// NewAesKeyGenParams creates a new AesKeyGenParams instance from a goja.Value.
//
// The given value should be goja exportable to the AesKeyGenParams type. Its
// fields will be validated, and normalized.
func NewAesKeyGenParams(rt *goja.Runtime, v goja.Value) (AesKeyGenParams, error) {
	if v == nil {
		return AesKeyGenParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params AesKeyGenParams
	if err := rt.ExportTo(v, &params); err != nil {
		return AesKeyGenParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	if err := params.Validate(); err != nil {
		return AesKeyGenParams{}, err
	}

	params.Normalize()

	return params, nil
}

// Ensure AesKeyGenParams implements the Validator interface.
var _ Validator = &AesKeyGenParams{}

// Validate validates the AesKeyGenParams instance fits the specifications
// requirements. It implements the Validator interface.
func (a AesKeyGenParams) Validate() error {
	if a.Name == "" {
		return NewError(0, SyntaxError, "name property is required")
	}

	var (
		isAesCbc = strings.EqualFold(a.Name, AESCbc)
		isAesCtr = strings.EqualFold(a.Name, AESCtr)
		isAesGcm = strings.EqualFold(a.Name, AESGcm)
		isAesKw  = strings.EqualFold(a.Name, AESKw)
	)

	if !isAesCbc && !isAesCtr && !isAesGcm && !isAesKw {
		return NewError(0, NotSupportedError, "name property should be either AES-CBC, AES-CTR, or AES-GCM")
	}

	if a.Length != 128 && a.Length != 192 && a.Length != 256 {
		return NewError(0, OperationError, "length property should be either 128, 192, or 256")
	}

	return nil
}

// Ensure AesKeyGenParams implements the Normalizer interface.
var _ Normalizer = &AesKeyGenParams{}

// Normalize normalizes the AesKeyGenParams instance. It implements the
// Normalizer interface.
func (a *AesKeyGenParams) Normalize() {
	a.Name = NormalizeAlgorithmName(a.Name)
}

// Ensure AesKeyGenParams implements the CryptoKeyGenerator interface.
// We expect Aes crypto keys to hold their data as []byte.
var _ CryptoKeyGenerator[[]byte] = &AesKeyGenParams{}

// GenerateKey generates a new AES key.
//
// It implements the CryptoKeyGenerator interface.
func (a AesKeyGenParams) GenerateKey(
	// rt *goja.Runtime,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (*CryptoKey[[]byte], error) {
	// 1.
	for _, usage := range keyUsages {
		if strings.EqualFold(a.Algorithm.Name, AESKw) {
			switch usage {
			case WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage:
				continue
			default:
				return nil, NewError(0, SyntaxError, "invalid key usage")
			}
		} else {
			switch usage {
			case EncryptCryptoKeyUsage, DecryptCryptoKeyUsage, WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage:
				continue
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
	return &key, nil
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
