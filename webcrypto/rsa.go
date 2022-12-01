package webcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
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

// exportRSAKey exports a RSA key to a given format.
// As defined in the ExportKey section of each RSA algorithm
// described in the [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#rsassa-pkcs1-operations
func exportRSAKey(rt *goja.Runtime, format KeyFormat, key goja.Value) (goja.Value, error) {
	switch format {
	case SpkiKeyFormat:
		return exportRSAKeyAsSpki(rt, key)
	case Pkcs8KeyFormat:
		return exportRSAKeyAsPkcs8(rt, key)
	case JwkKeyFormat:
		return exportRSAKeyAsJwk(rt, key)
	default:
		return nil, NewError(0, NotSupportedError, "unsupported key format")
	}
}

func exportRSAKeyAsSpki(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// 1.
	var cryptoKey CryptoKey[*rsa.PublicKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a public key")
	}

	// 2.
	if cryptoKey.handle == nil {
		return nil, NewError(0, OperationError, "key is not valid, no data")
	}

	// 3.1.
	if cryptoKey.Type != PublicCryptoKeyType {
		return nil, NewError(0, InvalidAccessError, "key is not a public key")
	}

	// 3.2.
	// TODO: this is based on the assumption that this stdlib function does
	// the steps described in the specs. Verify and remove me.
	data, err := x509.MarshalPKIXPublicKey(cryptoKey.handle)
	if err != nil {
		return nil, NewError(0, OperationError, "failed to marshal public key")
	}

	return rt.ToValue(rt.NewArrayBuffer(data)), nil
}

func exportRSAKeyAsPkcs8(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// 1.
	var cryptoKey CryptoKey[*rsa.PrivateKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	// 2.
	if cryptoKey.handle == nil {
		return nil, NewError(0, OperationError, "key is not valid, no data")
	}

	// TODO: verify that this actually complies with the specs (it should)
	data, err := x509.MarshalPKCS8PrivateKey(cryptoKey.handle)
	if err != nil {
		return nil, NewError(0, OperationError, "failed to marshal private key")
	}

	return rt.ToValue(rt.NewArrayBuffer(data)), nil
}

//nolint:funlen
func exportRSAKeyAsJwk(rt *goja.Runtime, key goja.Value) (goja.Value, error) {
	// There's a trick here, as we need to handle both public and private keys
	// but we have a concrete type for them. Conviniently, Go exposes crypto
	// keys in a way that public key are contained by private keys, so we can
	// use this to our advantage.
	var cryptoKey CryptoKey[*rsa.PrivateKey]
	err := rt.ExportTo(key, cryptoKey)
	if err != nil {
		return nil, NewError(0, InvalidAccessError, "key is not a private key")
	}

	keyAlgorithm, ok := cryptoKey.Algorithm.(RsaHashedKeyAlgorithm)
	if !ok {
		return nil, NewError(0, ImplementationError, "unable to extract key data")
	}

	// 2.1.
	jwk := JSONWebKey{}

	// 2.2.
	jwk.KeyType = "RSA"

	// 2.3.
	var prefix string
	switch keyAlgorithm.Name {
	case RSASsaPkcs1v15:
		prefix = "RS"
	case RSAPss:
		prefix = "PS"
	case RSAOaep:
		prefix = "RSA-OAEP-"
	default:
		return nil, NewError(0, NotSupportedError, "unsupported algorithm")
	}

	var suffix string
	switch keyAlgorithm.Hash.Name {
	case Sha1:
		if keyAlgorithm.Name == RSAOaep {
			suffix = ""
		} else {
			suffix = "1"
		}
	case Sha256:
		suffix = "256"
	case Sha384:
		suffix = "384"
	case Sha512:
		suffix = "512"
	default:
		return nil, NewError(0, NotSupportedError, "unsupported hash algorithm")
	}

	jwk.Algorithm = prefix + suffix

	// 3.4.
	// As defined in the JWA RFC: https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1
	jwk.N = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.N.Bytes())
	jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(cryptoKey.handle.E)).Bytes())

	// 3.5.
	// As defined in the JWA RFC: https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2
	if cryptoKey.Type == PrivateCryptoKeyType {
		jwk.D = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.D.Bytes())
		jwk.P = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Primes[0].Bytes())
		jwk.Q = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Primes[1].Bytes())
		jwk.Dp = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Precomputed.Dp.Bytes())
		jwk.Dq = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Precomputed.Dq.Bytes())
		jwk.Qi = base64.RawURLEncoding.EncodeToString(cryptoKey.handle.Precomputed.Qinv.Bytes())

		// 3.5.2.
		// TODO: "If the underlying RSA private key represented by
		// the [[handle]] internal slot of key is represented by more
		// than two primes, set the attribute named oth of jwk according
		// to the corresponding definition in JSON Web Algorithms, Section 6.3.2.7"
	}

	// 4.
	copy(jwk.KeyOps, cryptoKey.Usages)

	// 5.
	jwk.Extractable = cryptoKey.Extractable

	// 6.
	return rt.ToValue(jwk), nil
}
