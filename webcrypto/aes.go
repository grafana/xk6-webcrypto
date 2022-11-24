package webcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

	// 5. 6. 7. 8. 9. 10. 11.
	key := CryptoKey[[]byte]{}

	// 6. 7. 8.
	algorithm := AesKeyAlgorithm{}
	algorithm.Name = a.Algorithm.Name
	algorithm.Length = a.Length

	// 9.. 10. 11.
	key.Algorithm = algorithm
	key.Type = SecretCryptoKeyType
	key.Extractable = extractable
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

// AesCbcParams represents the object that should be passed as the algorithm parameter
// into `SubtleCrypto.Encrypt`, `SubtleCrypto.Decrypt`, `SubtleCrypto.WrapKey`, or
// `SubtleCrypto.UnwrapKey`, when using the AES-CBC algorithm.
type AesCbcParams struct {
	Algorithm

	// Iv holds (an ArrayBuffer, a TypedArray, or a DataView) the initialization vector.
	// Must be 16 bytes, unpredictable, and preferably cryptographically random.
	// However, it need not be secret (for example, it may be transmitted unencrypted along with the ciphertext).
	Iv []byte `json:"iv"`
}

// NewAesCbcParams creates a new AesCbcParams instance from the given goja.Value.
func NewAesCbcParams(rt *goja.Runtime, v goja.Value) (AesCbcParams, error) {
	if v == nil {
		return AesCbcParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params AesCbcParams
	if err := rt.ExportTo(v, &params); err != nil {
		return AesCbcParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	ivValue := v.ToObject(rt).Get("iv")
	if ivValue == nil {
		return AesCbcParams{}, NewError(0, SyntaxError, "iv property is required")
	}

	iv, ok := ivValue.Export().(goja.ArrayBuffer)
	if !ok {
		return AesCbcParams{}, NewError(0, SyntaxError, "iv is not an ArrayBuffer, nor a TypedArray, nor a DataView")
	}

	params.Iv = iv.Bytes()

	return params, nil
}

// Ensure AesCbcParams implements the Encrypter interface.
var _ Encrypter = &AesCbcParams{}

// Encrypt encrypts the given data using the given key and algorithm.
func (a *AesCbcParams) Encrypt(
	rt *goja.Runtime,
	key goja.Value,
	plaintext []byte,
) (goja.ArrayBuffer, error) {
	cryptoKey, ok := key.Export().(CryptoKey[[]byte])
	if !ok {
		return goja.ArrayBuffer{}, NewError(0, ImplementationError, "key canno't be casted to CryptoKey")
	}

	// 1.
	// Note that aes.BlockSize stands for the `k` variable as per the specification.
	if len(a.Iv) != aes.BlockSize {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "iv length is not 16 bytes")
	}

	// 2.
	paddedPlainText, err := pKCS7Pad(plaintext, aes.BlockSize)
	if err != nil {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "could not pad plaintext")
	}

	// 3.
	block, err := aes.NewCipher(cryptoKey.handle)
	if err != nil {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "could not create cipher")
	}

	ciphertext := make([]byte, len(paddedPlainText))
	cbc := cipher.NewCBCEncrypter(block, a.Iv)
	cbc.CryptBlocks(ciphertext, paddedPlainText)

	return rt.NewArrayBuffer(ciphertext), nil
}

// pKCS7Padding adds PKCS7 padding to the given plaintext.
// It implements section 10.3 of [RFC 2315].
//
// [RFC 2315]: https://www.rfc-editor.org/rfc/rfc2315#section-10.3
func pKCS7Pad(plaintext []byte, k int) ([]byte, error) {
	if k <= 0 {
		return nil, ErrInvalidBlockSize
	}

	if len(plaintext) == 0 {
		return nil, ErrInvalidPkcs7Data
	}

	l := len(plaintext)
	padding := k - (l % k)
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, paddingText...), nil
}

var (
	// ErrInvalidBlockSize is returned when the given block size is invalid.
	ErrInvalidBlockSize = errors.New("invalid block size")

	// ErrInvalidPkcs7Data is returned when the given data is invalid.
	ErrInvalidPkcs7Data = errors.New("invalid PKCS7 data")
)

// AesGcmParams represents the object that should be passed as the algorithm [parameter]
// into `SubtleCrypto.Encrypt`, `SubtleCrypto.Decrypt`, `SubtleCrypto.WrapKey`, or
// `SubtleCrypto.UnwrapKey`, when using the AES-GCM algorithm.
type AesGcmParams struct {
	Algorithm

	// Iv holds (an ArrayBuffer, a TypedArray, or a DataView) the initialization vector.
	// Must be 16 bytes, unpredictable, and preferably cryptographically random.
	// However, it need not be secret (for example, it may be transmitted unencrypted along with the ciphertext).
	Iv []byte `json:"iv"`

	// AdditionalData holds (an ArrayBuffer, a TypedArray, or a DataView) the additional authenticated data.
	// This is data that is authenticated but not encrypted, and must also be provided during decryption.
	// If this value is not provided, it is treated as an empty array.
	AdditionalData []byte `json:"additionalData"`

	// TagLength holds (unsigned long) the length of the authentication tag, in bits. May be 0 - 128.
	// If this value is not provided, it is treated as 128.
	TagLength *int `json:"tagLength"`
}

// NewAesGcmParams creates a new AesGcmParams object from the given goja.Value.
func NewAesGcmParams(rt *goja.Runtime, v goja.Value) (AesGcmParams, error) {
	if v == nil {
		return AesGcmParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params AesGcmParams
	if err := rt.ExportTo(v, &params); err != nil {
		return AesGcmParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	ivValue := v.ToObject(rt).Get("iv")
	if ivValue == nil {
		return AesGcmParams{}, NewError(0, SyntaxError, "iv property is required")
	}

	iv, ok := ivValue.Export().(goja.ArrayBuffer)
	if !ok {
		return AesGcmParams{}, NewError(0, SyntaxError, "iv is not an ArrayBuffer, nor a TypedArray, nor a DataView")
	}

	params.Iv = iv.Bytes()

	if additionalDataValue := v.ToObject(rt).Get("additionalData"); additionalDataValue != nil {
		additionalData, ok := additionalDataValue.Export().(goja.ArrayBuffer)
		if !ok {
			err := NewError(0, SyntaxError, "additionalData is not an ArrayBuffer, nor a TypedArray, nor a DataView")
			return AesGcmParams{}, err
		}

		params.AdditionalData = additionalData.Bytes()
	}

	if tagLengthValue := v.ToObject(rt).Get("tagLength"); tagLengthValue != nil {
		tagLength, ok := tagLengthValue.Export().(*int)
		if !ok {
			return AesGcmParams{}, NewError(0, SyntaxError, "tagLength is not an unsigned long")
		}

		params.TagLength = tagLength
	}

	params.Normalize()

	return params, nil
}

// Ensure AesCbcParams implements the Encrypter interface.
var _ Encrypter = &AesGcmParams{}

// Encrypt encrypts the given plaintext using the given key and the algorithm
// specified by the receiver.
func (a *AesGcmParams) Encrypt(rt *goja.Runtime, key goja.Value, plaintext []byte) (goja.ArrayBuffer, error) {
	cryptoKey, ok := key.Export().(CryptoKey[[]byte])
	if !ok {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "key is not a CryptoKey")
	}

	// 1.
	// As described in section 8 of AES-GCM [NIST SP800-38D].
	// [NIST SP800-38D] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	if uint64(len(plaintext)) > maxAesGcmPlaintextLength {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "plaintext is too long")
	}

	// 2.
	// TODO: Go documentation mention the Nonce/Iv needs to be aes.NonceSize size.
	// As described in section 8 of AES-GCM [NIST SP800-38D].
	// [NIST SP800-38D] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	if len(a.Iv) < 1 && uint64(len(a.Iv)) > maxAesGcmIvLength {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "iv length is too long")
	}

	// 3.
	// As described in section 8 of AES-GCM [NIST SP800-38D].
	// [NIST SP800-38D] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	if a.AdditionalData != nil && uint64(len(a.AdditionalData)) > maxAesGcmAdditionalDataLength {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "additionalData length is too long")
	}

	// 4.
	var tagLength int
	if a.TagLength == nil {
		tagLength = 128
	} else {
		switch *a.TagLength {
		case 96, 104, 112, 120, 128:
			tagLength = *a.TagLength
		case 32, 64:
			// Go's GCM implementation does not support 32 or 64 bit tag lengths.
			return goja.ArrayBuffer{}, NewError(0, ImplementationError, "support for tag length of 32 and 64 is unimplemented")
		default:
			return goja.ArrayBuffer{}, NewError(0, OperationError, "tagLength is not 0, 32, 64, 96, 104, 112, 120, or 128")
		}
	}

	// 6.
	block, err := aes.NewCipher(cryptoKey.handle)
	if err != nil {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "could not create cipher")
	}

	gcm, err := cipher.NewGCMWithTagSize(block, tagLength/8)
	if err != nil {
		panic(err.Error())
	}

	// The Golang AES GCM cipher only supports a Nonce/Iv length of 12 bytes,
	// as opposed to the looser requirements of the Web Crypto API spec.
	if len(a.Iv) != gcm.NonceSize() {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "iv length is not 12")
	}

	// 7. 8.
	// Note that the `Seal` operation adds the tag component at the end of
	// the ciphertext.
	return rt.NewArrayBuffer(gcm.Seal(nil, a.Iv, plaintext, a.AdditionalData)), nil
}

// maxAesGcmPlaintextLength holds the value (2 ^ 39) - 256 as specified in
// The [Web Crypto API spec] for the AES-GCM algorithm encryption operation.
//
// [Web Crypto API spec]: https://www.w3.org/TR/WebCryptoAPI/#aes-gcm-encryption-operation
const maxAesGcmPlaintextLength uint64 = 549755813632

// maxAesGcmIvLength holds the value 2 ^ 64 - 1 as specified in
// the [Web Crypto API spec] for the AES-GCM algorithm encryption operation.
//
// [Web Crypto API spec]: https://www.w3.org/TR/WebCryptoAPI/#aes-gcm-encryption-operation
const maxAesGcmIvLength uint64 = 18446744073709551615

// maxAesGcmAdditionalDataLength holds the value 2 ^ 64 - 1 as specified in
// the [Web Crypto API spec] for the AES-GCM algorithm encryption operation.
//
// [Web Crypto API spec]: https://www.w3.org/TR/WebCryptoAPI/#aes-gcm-encryption-operation
const maxAesGcmAdditionalDataLength uint64 = 18446744073709551615

// AesCtrParams holds the [parameters] for the AES-CTR algorithm.
//
// [parameters]: https://www.w3.org/TR/WebCryptoAPI/#aes-ctr-params
type AesCtrParams struct {
	Algorithm

	// Counter holds the initial value of the counter block.
	//
	// Counter MUST be 16 bytes (the AES block size).
	// The counter bits are the rightmost length bits of the counter block.
	// The rest of the counter block is for the nonce/iv. The counter bits are
	// incremented using the standard incrementing function specified in
	// NIST SP 800-38A Appendix B.1: the counter bits are interpreted as a big-endian integer and
	// incremented by one.
	Counter []byte

	// The length, in bits, of the rightmost part of the counter block
	// that is incremented.
	//
	// the number of bits in the counter block that are used for the actual counter.
	// The counter must be big enough that it doesn't wrap: if the message is n blocks
	// and the counter is m bits long, then the following must be true: n <= 2^m.
	// The NIST SP800-38A standard, which defines CTR, suggests that the counter
	// should occupy half of the counter block (see Appendix B.2), so for AES it would be 64.
	Length uint8
}

// NewAesCtrParams returns a new AesCtrParams instance given a goja.Value.
func NewAesCtrParams(rt *goja.Runtime, v goja.Value) (AesCtrParams, error) {
	if v == nil {
		return AesCtrParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params AesCtrParams
	if err := rt.ExportTo(v, &params); err != nil {
		return AesCtrParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	counterValue := v.ToObject(rt).Get("counter")
	if counterValue == nil {
		return AesCtrParams{}, NewError(0, SyntaxError, "counter property is required")
	}

	counter, ok := counterValue.Export().(goja.ArrayBuffer)
	if !ok {
		return AesCtrParams{}, NewError(0, SyntaxError, "counter is not an ArrayBuffer, nor a TypedArray, nor a DataView")
	}

	params.Counter = counter.Bytes()

	lengthValue := v.ToObject(rt).Get("length")
	if lengthValue == nil {
		return AesCtrParams{}, NewError(0, SyntaxError, "length property is required")
	}

	length, ok := lengthValue.Export().(uint8)
	if !ok {
		return AesCtrParams{}, NewError(0, SyntaxError, "length is not an unsigned long")
	}

	params.Length = length

	params.Normalize()

	return params, nil
}

// Ensure AesCbcParams implements the Encrypter interface.
var _ Encrypter = &AesCtrParams{}

// Encrypt implements the Encrypter interface for the AesCtrParams type.
//
// Note that in Ctr mode, the plaintext size does not need to be a multiple
// of the block size.
func (a *AesCtrParams) Encrypt(rt *goja.Runtime, key goja.Value, plaintext []byte) (goja.ArrayBuffer, error) {
	cryptoKey, ok := key.Export().(CryptoKey[[]byte])
	if !ok {
		return goja.ArrayBuffer{}, NewError(0, TypeError, "key is not a CryptoKey")
	}

	// 1.
	// Note that the counter is referred to as the "iv" in Go standard library
	if len(a.Counter) != aes.BlockSize {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "counter length is not 16")
	}

	// 2.
	if a.Length == 0 || a.Length > 128 {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "length is not 1-128")
	}

	// 3.
	block, err := aes.NewCipher(cryptoKey.handle)
	if err != nil {
		return goja.ArrayBuffer{}, NewError(0, OperationError, "could not create cipher")
	}

	ciphertext := make([]byte, len(plaintext))
	ctr := cipher.NewCTR(block, a.Counter)
	ctr.XORKeyStream(ciphertext, plaintext)

	return rt.NewArrayBuffer(ciphertext), nil
}
