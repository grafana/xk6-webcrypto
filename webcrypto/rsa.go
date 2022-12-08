package webcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

// Ensure AesKeyGenParams implements the From interface.
var _ From[map[string]interface{}, RsaHashedKeyGenParams] = RsaHashedKeyGenParams{}

// From implements the From interface for RsaHashedKeyGenParams, and initializes the
// instance from a map[string]interface{}.
//
//nolint:funlen,gocognit
func (r RsaHashedKeyGenParams) From(dict map[string]interface{}) (RsaHashedKeyGenParams, error) {
	params := RsaHashedKeyGenParams{}
	nameFound := false
	modulusLengthFound := false
	publicExponentFound := false
	hashFound := false

	for key, value := range dict {
		if strings.EqualFold(key, "name") {
			name, ok := value.(string)
			if !ok {
				return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "name property should hold a string")
			}

			if !IsAlgorithm(name) {
				return RsaHashedKeyGenParams{}, NewError(0, NotSupportedError, "unsupported algorithm name")
			}

			params.Name = name
			nameFound = true
			continue
		}

		if strings.EqualFold(key, "modulusLength") {
			length, ok := value.(int64)
			if !ok {
				return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "modulusLength property should hold a number")
			}

			params.ModulusLength = uint32(length)
			modulusLengthFound = true
			continue
		}

		if strings.EqualFold(key, "publicExponent") {
			exponent, ok := value.([]byte)
			if !ok && exponent != nil {
				return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "publicExponent property should hold a Uint8Array")
			}

			params.PublicExponent = exponent
			publicExponentFound = true
			continue
		}

		// As opposed to HmacKeyGenParams, RsaHashedKeyGenParams' hash
		// can only be a string.
		if strings.EqualFold(key, "hash") {
			hash, ok := value.(string)
			if !ok {
				return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "hash property should hold a string")
			}

			hash = strings.ToUpper(hash)

			if !IsAlgorithm(hash) && !IsHashAlgorithm(hash) {
				return RsaHashedKeyGenParams{}, NewError(0, NotSupportedError, "unsupported hashing algorithm name")
			}

			params.Hash = hash
			hashFound = true
			continue
		}
	}

	if !nameFound {
		return RsaHashedKeyGenParams{}, NewError(0, NotSupportedError, "missing algorithm name")
	}

	if !modulusLengthFound {
		return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "missing modulusLength property")
	}

	if !publicExponentFound {
		return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "missing publicExponent property")
	}

	if !hashFound {
		return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "missing hash algorithm name")
	}

	return params, nil
}

// Ensure AesKeyGenParams implements the From interface.
var _ KeyGenerator = &RsaHashedKeyGenParams{}

// GenerateKey implements the KeyGenerator interface for RsaHashedKeyGenParams, and generates
// a new RSA key pair.
func (r RsaHashedKeyGenParams) GenerateKey(
	rt *goja.Runtime,
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (goja.Value, error) {
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
			default:
				return nil, NewError(0, SyntaxError, "invalid key usage")
			}
		} else {
			switch usage {
			case SignCryptoKeyUsage, VerifyCryptoKeyUsage:
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
	publicKey.Usages = UsageIntersection(keyUsages, []CryptoKeyUsage{VerifyCryptoKeyUsage})
	publicKey.handle = keyPair.Public()

	// 14. 15. 16. 17. 18.
	privateKey := CryptoKey[crypto.PrivateKey]{}
	privateKey.Type = PrivateCryptoKeyType
	privateKey.Algorithm = algorithm
	privateKey.Extractable = extractable
	privateKey.Usages = UsageIntersection(keyUsages, []CryptoKeyUsage{SignCryptoKeyUsage})
	privateKey.handle = keyPair

	// We apply the generateKey 8. step here, as we return a goja.Value
	// instead of a CryptoKey(Pair).
	if privateKey.Usages == nil || len(privateKey.Usages) == 0 {
		return nil, NewError(0, SyntaxError, "the keyUsages argument must contain at least one valid usage for the algorithm")
	}

	// 19. 20. 21.
	result := CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey]{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	// 22.
	return rt.ToValue(result), nil
}

type RsaOaepParams struct {
	Algorithm

	// Label holds (an ArrayBuffer, a TypedArray, or a DataView) an array of bytes that does not
	// itself need to be encrypted but which should be bound to the ciphertext.
	// A digest of the label is part of the input to the encryption operation.
	//
	// Unless your application calls for a label, you can just omit this argument
	// and it will not affect the security of the encryption operation.
	Label []byte `json:"label"`
}

// Ensure RsaOaepParams implements the From interface.
var _ From[map[string]interface{}, RsaOaepParams] = &RsaOaepParams{}

// From produces an output of type Output from the
// content of the given input.
func (r RsaOaepParams) From(dict map[string]interface{}) (RsaOaepParams, error) {
	algorithm, err := Algorithm{}.From(dict)
	if err != nil {
		return RsaOaepParams{}, err
	}

	r.Algorithm = algorithm

	for key, value := range dict {
		if strings.EqualFold(key, "label") {
			label, ok := value.(goja.ArrayBuffer)
			if !ok {
				return RsaOaepParams{}, NewWebCryptoError(0, SyntaxError, "label is not an ArrayBuffer, nor a TypedArray, nor a DataView")
			}

			r.Label = label.Bytes()
			break
		}
	}

	return r, nil
}

// Ensure RsaOaepParams implements the Decrypter interface.
var _ Decrypter = &RsaOaepParams{}

// Decrypt decrypts the given ciphertext using the given key.
func (r *RsaOaepParams) Decrypt(rt *goja.Runtime, key goja.Value, ciphertext []byte) (goja.ArrayBuffer, error) {
	cryptoKeyPair := key.Export().(CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey])
	cryptoKey := cryptoKeyPair.PrivateKey

	// 1.
	if cryptoKey.Type != PrivateCryptoKeyType {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, InvalidAccessError, "key is not a private key")
	}

	// 2.
	label := r.Label

	// Fetch the hash function described by the key's algorithm.
	// As instructed in 3.
	hash, err := Hasher(cryptoKey.Algorithm.(RsaHashedKeyAlgorithm).Hash.Name)
	if err != nil {
		return goja.ArrayBuffer{}, NewWebCryptoError(0, ImplementationError, "failed to fetch hash function")
	}

	// 3. 5.
	plaintext, err := rsa.DecryptOAEP(hash(), rand.Reader, cryptoKey.handle.(*rsa.PrivateKey), ciphertext, label)
	if err != nil {
		// 4.
		return goja.ArrayBuffer{}, NewWebCryptoError(0, OperationError, err.Error())
	}

	return rt.NewArrayBuffer(plaintext), nil
}
