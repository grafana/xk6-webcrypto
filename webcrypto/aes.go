package webcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

// AESCbcParams represents the object that should be passed as the algorithm parameter
// into `SubtleCrypto.Encrypt`, `SubtleCrypto.Decrypt`, `SubtleCrypto.WrapKey`, or
// `SubtleCrypto.UnwrapKey`, when using the AES-CBC algorithm.
type AesCbcParams struct {
	Algorithm

	// Iv holds (an ArrayBuffer, a TypedArray, or a DataView) the initialization vector.
	// Must be 16 bytes, unpredictable, and preferably cryptographically random.
	// However, it need not be secret (for example, it may be transmitted unencrypted along with the ciphertext).
	Iv []byte `json:"iv"`
}

// Ensure RsaOaepParams implements the From interface.
var _ From[map[string]interface{}, AesCbcParams] = &AesCbcParams{}

// FIXME: This doesn't work, we always end up in the "iv" is not a byte array case.
// From produces an output of type Output from the
// content of the given input.
func (a AesCbcParams) From(dict map[string]interface{}) (AesCbcParams, error) {
	algorithm, err := Algorithm{}.From(dict)
	if err != nil {
		return AesCbcParams{}, err
	}

	a.Algorithm = algorithm

	ivFound := false

	for key, value := range dict {
		if strings.EqualFold(key, "iv") {
			iv, ok := value.(goja.ArrayBuffer)
			if !ok {
				return AesCbcParams{}, NewWebCryptoError(0, SyntaxError, "iv is not an ArrayBuffer, nor a TypedArray, nor a DataView")
			}

			a.Iv = iv.Bytes()
			ivFound = true
			break
		}
	}

	if !ivFound {
		return AesCbcParams{}, NewWebCryptoError(0, SyntaxError, "iv property is required")
	}

	return a, nil
}

// Ensure AesCbcParams implements the Decrypter interface.
var _ Decrypter = &AesCbcParams{}

func (a *AesCbcParams) Decrypt(rt *goja.Runtime, key goja.Value, ciphertext []byte) (goja.ArrayBuffer, error) {
	cryptoKey := key.Export().(CryptoKey[[]byte])

	// 1.
	if len(a.Iv) != aes.BlockSize {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "iv length is not 16 bytes")
	}

	// 2.
	block, err := aes.NewCipher(cryptoKey.handle)
	if err != nil {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "could not create cipher")
	}

	paddedPlainText := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, a.Iv)
	cbc.CryptBlocks(paddedPlainText, ciphertext)

	// 3. 4. 5.
	plaintext, err := pKCS7Strip(paddedPlainText, aes.BlockSize)
	if err != nil {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "could not strip padding")
	}

	// 6.
	return rt.NewArrayBuffer(plaintext), nil
}

func pKCS7Strip(data []byte, k int) ([]byte, error) {
	length := len(data)

	if length == 0 {
		return nil, ErrInvalidPkcs7Data
	}

	if length%k != 0 {
		return nil, ErrInvalidPkcs7Data
	}

	padLength := int(data[length-1])
	paddingText := bytes.Repeat([]byte{byte(padLength)}, padLength)
	if padLength > k || padLength == 0 || !bytes.HasSuffix(data, paddingText) {
		return nil, ErrInvalidPkcs7Data
	}

	return data[:length-padLength], nil
}

var (
	// ErrInvalidBlockSize is returned when the block size is invalid.
	ErrInvalidBlockSize = errors.New("invalid block size")

	// ErrInvalidPKCS7Data is returned when the PKCS7 data is invalid.
	ErrInvalidPkcs7Data = errors.New("invalid PKCS7 data (empty or not padded)")
)

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

// Ensure RsaOaepParams implements the From interface.
var _ From[map[string]interface{}, AesGcmParams] = &AesGcmParams{}

// From produces an output of type Output from the
// content of the given input.
func (a AesGcmParams) From(dict map[string]interface{}) (AesGcmParams, error) {
	algorithm, err := Algorithm{}.From(dict)
	if err != nil {
		return AesGcmParams{}, err
	}

	a.Algorithm = algorithm

	ivFound := false

	for key, value := range dict {
		if strings.EqualFold(key, "iv") {
			iv, ok := value.(goja.ArrayBuffer)
			if !ok {
				return AesGcmParams{}, NewWebCryptoError(0, SyntaxError, "iv is not an ArrayBuffer, nor a TypedArray, nor a DataView")
			}

			a.Iv = iv.Bytes()
			ivFound = true
			continue
		}

		if strings.EqualFold(key, "additionalData") {
			additionalData, ok := value.(goja.ArrayBuffer)
			if !ok {
				return AesGcmParams{}, NewWebCryptoError(0, SyntaxError, "additionalData is not an ArrayBuffer, nor a TypedArray, nor a DataView")
			}

			a.AdditionalData = additionalData.Bytes()
			continue
		}

		if strings.EqualFold(key, "tagLength") {
			tagLength, ok := value.(int)
			if !ok {
				return AesGcmParams{}, NewWebCryptoError(0, SyntaxError, "tagLength is not an unsigned long")
			}

			a.TagLength = &tagLength
			continue
		}
	}

	if !ivFound {
		return AesGcmParams{}, NewWebCryptoError(0, SyntaxError, "iv is not provided")
	}

	return a, nil
}

// Ensure AesGcmParams implements the Decrypter interface.
var _ Decrypter = &AesGcmParams{}

// Decrypt decrypts the given ciphertext using the given key and parameters.
func (a *AesGcmParams) Decrypt(rt *goja.Runtime, key goja.Value, ciphertext []byte) (goja.ArrayBuffer, error) {
	cryptoKey := key.Export().(CryptoKey[[]byte])

	// 1.
	var tagLength int
	if a.TagLength == nil {
		tagLength = 128
	} else {
		switch *a.TagLength {
		case 96, 104, 112, 120, 128:
			tagLength = *a.TagLength
		case 32, 64:
			// Go's GCM implementation does not support 32 or 64 bit tag lengths.
			return goja.ArrayBuffer{}, NewWebCryptoError(0, ImplementationError, "support for tag length of 32 and 64 is unimplemented")
		default:
			return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "tagLength is not 0, 32, 64, 96, 104, 112, 120, or 128")
		}
	}

	// 2.
	// Note that we multiply the lenght of the ciphertext by 8, in order
	// to get the length in bits.
	if len(ciphertext)*8 < tagLength {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "ciphertext is too short")
	}

	// 3.
	if len(a.Iv) < 1 && uint64(len(a.Iv)) > maxAesGcmIvLength {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "iv length is too long")
	}

	// 4.
	if a.AdditionalData != nil && uint64(len(a.AdditionalData)) > maxAesGcmAdditionalDataLength {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "additionalData length is too long")
	}

	// 5. 6. Are not necessary as Go's implementation of AES GCM does that for us.

	// 7. 8.
	block, err := aes.NewCipher(cryptoKey.handle)
	if err != nil {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "could not create cipher")
	}

	gcm, err := cipher.NewGCMWithTagSize(block, tagLength/8)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := gcm.Open(nil, a.Iv, ciphertext, a.AdditionalData)
	if err != nil {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "could not decrypt")
	}

	return rt.NewArrayBuffer(plaintext), nil
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

// Ensure RsaOaepParams implements the From interface.
var _ From[map[string]interface{}, AesCtrParams] = &AesCtrParams{}

func (a AesCtrParams) From(dict map[string]interface{}) (AesCtrParams, error) {
	algorithm, err := Algorithm{}.From(dict)
	if err != nil {
		return AesCtrParams{}, err
	}

	a.Algorithm = algorithm

	counterFound := false
	lengthFound := false

	for key, value := range dict {
		if strings.EqualFold(key, "counter") {
			counter, ok := value.(goja.ArrayBuffer)
			if !ok {
				return AesCtrParams{}, NewWebCryptoError(0, SyntaxError, "counter is not an ArrayBuffer, nor a TypedArray, nor a DataView")
			}

			a.Counter = counter.Bytes()
			counterFound = true
			continue
		}

		if strings.EqualFold(key, "length") {
			length, ok := value.(int64)
			if !ok {
				return AesCtrParams{}, NewWebCryptoError(0, SyntaxError, "length is not an unsigned long")
			}

			a.Length = uint8(length)
			lengthFound = true
			continue
		}
	}

	if !counterFound {
		return AesCtrParams{}, NewWebCryptoError(0, SyntaxError, "counter is not provided")
	}

	if !lengthFound {
		return AesCtrParams{}, NewWebCryptoError(0, SyntaxError, "length is not provided")
	}

	return a, nil
}

// Ensure AesCtrParams implements the Decrypter interface.
var _ Decrypter = &AesCtrParams{}

// FIXME: Not sure how, but we need to use the length somehow? Or can we safely ignore because of Go's implementation?
// Decrypt implements the Decrypter interface for the AesCtrParams type.
//
// Note that in Ctr mode, the plaintext size does not need to be a multiple
// of the block size.
func (a *AesCtrParams) Decrypt(rt *goja.Runtime, key goja.Value, ciphertext []byte) (goja.ArrayBuffer, error) {
	cryptoKey := key.Export().(CryptoKey[[]byte])

	// 1.
	if len(a.Counter) != aes.BlockSize {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "counter length is not 16")
	}

	// 2.
	if a.Length == 0 || a.Length > 128 {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "length is not 1-128")
	}

	// 3.
	block, err := aes.NewCipher(cryptoKey.handle)
	if err != nil {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, "could not create cipher")
	}

	plaintext := make([]byte, len(ciphertext))
	ctr := cipher.NewCTR(block, a.Counter)
	ctr.XORKeyStream(plaintext, ciphertext)

	return rt.NewArrayBuffer(plaintext), nil
}
