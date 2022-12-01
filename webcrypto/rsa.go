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

// NewRsaHashedKeyGenParams creates a new RsaHashedKeyGenParams instance from a goja.Value.
//
//nolint:dupl
func NewRsaHashedKeyGenParams(rt *goja.Runtime, v goja.Value) (RsaHashedKeyGenParams, error) {
	if v == nil {
		return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "algorithm is required")
	}

	var params RsaHashedKeyGenParams
	if err := rt.ExportTo(v, &params); err != nil {
		return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "algorithm is invalid")
	}

	// Because the hash field can either be a string or an object, we need to
	// handle it specifically.
	if hash, ok := v.ToObject(rt).Get("hash").Export().(string); ok {
		params.Hash = hash
	} else {
		var hash Algorithm
		if err := rt.ExportTo(v.ToObject(rt).Get("hash"), &hash); err != nil {
			return RsaHashedKeyGenParams{}, NewError(0, SyntaxError, "hash algorithm is invalid")
		}
		params.Hash = hash.Name
	}

	if err := params.Validate(); err != nil {
		return RsaHashedKeyGenParams{}, err
	}

	params.Normalize()

	return params, nil
}

// Ensure RsaHashedKeyGenParams implements the Validator interface.
var _ Validator = &RsaHashedKeyGenParams{}

// Validate validates the RsaHashedKeyGenParams instance. It implements the
// Validator interface.
func (r RsaHashedKeyGenParams) Validate() error {
	if r.Name == "" {
		return NewError(0, SyntaxError, "name is required")
	}

	var (
		isRsaSsaPkcs1V15 = strings.EqualFold(r.Name, "RSASSA-PKCS1-v1_5")
		isRsaPss         = strings.EqualFold(r.Name, "RSA-PSS")
		isRsaOaep        = strings.EqualFold(r.Name, "RSA-OAEP")
	)

	if !isRsaSsaPkcs1V15 && !isRsaPss && !isRsaOaep {
		return NewError(0, NotSupportedError, "unsupported algorithm name")
	}

	if r.PublicExponent == nil {
		return NewError(0, OperationError, "publicExponent is required")
	}

	if len(r.PublicExponent) != 3 {
		return NewError(0, OperationError, "publicExponent must be 3 bytes")
	}

	if r.PublicExponent[0] != 0x01 || r.PublicExponent[1] != 0x00 || r.PublicExponent[2] != 0x01 {
		return NewError(0, OperationError, "publicExponent must be 0x010001")
	}

	if r.Hash == "" {
		return NewError(0, SyntaxError, "hash is required")
	}

	if !IsHashAlgorithm(r.Hash) {
		return NewError(0, NotSupportedError, "unsupported hash algorithm")
	}

	return nil
}

// Ensure RsaHashedKeyGenParams implements the Normalizer interface.
var _ Normalizer = &RsaHashedKeyGenParams{}

// Normalize normalizes the RsaHashedKeyGenParams instance. It implements
// the Normalizer interface.
func (r *RsaHashedKeyGenParams) Normalize() {
	r.Name = NormalizeAlgorithmName(r.Name)
	r.Hash = NormalizeHashAlgorithmName(r.Hash)
}

// Ensure RsaHashedKeyGenParams implements the CryptoKeyPairGenerator interface.
var _ CryptoKeyPairGenerator[crypto.PrivateKey, crypto.PublicKey] = &RsaHashedKeyGenParams{}

// GenerateKeyPair implements the CryptoKeyPairGenerator interface for RsaHashedKeyGenParams, and generates
// a new RSA key pair.
//
//nolint:funlen
func (r RsaHashedKeyGenParams) GenerateKeyPair(
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (*CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey], error) {
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
				continue
			default:
				return nil, NewError(0, SyntaxError, "invalid key usage")
			}
		} else {
			switch usage {
			case SignCryptoKeyUsage, VerifyCryptoKeyUsage:
				continue
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
	publicKey.Usages = Intersection(
		keyUsages,
		InferCryptoKeyUsages(algorithm.Name, PublicCryptoKeyType),
	)
	publicKey.handle = keyPair.Public()

	// 14. 15. 16. 17. 18.
	privateKey := CryptoKey[crypto.PrivateKey]{}
	privateKey.Type = PrivateCryptoKeyType
	privateKey.Algorithm = algorithm
	privateKey.Extractable = extractable
	privateKey.Usages = Intersection(
		keyUsages,
		InferCryptoKeyUsages(algorithm.Name, PrivateCryptoKeyType),
	)
	privateKey.handle = *keyPair

	// We apply the generateKey 8. step here, as we return a goja.Value
	// instead of a CryptoKey(Pair).
	if privateKey.Usages == nil || len(privateKey.Usages) == 0 {
		return nil, NewError(0, SyntaxError, "the keyUsages argument must contain at least one valid usage for the algorithm")
	}

	// 19. 20. 21.
	result := CryptoKeyPair[crypto.PrivateKey, crypto.PublicKey]{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	// 22.
	return &result, nil
}

// RsaHashedImportParams represents the parameters for importing an RSA key pair.
//
// See: https://www.w3.org/TR/WebCryptoAPI/#RsaHashedImportParams-dictionary
type RsaHashedImportParams struct {
	Algorithm

	// Hash contains the hash algorithm to use.
	Hash HashAlgorithmIdentifier `json:"hash"`
}

//nolint:unused,deadcode
func importRSAKey(
	rt *goja.Runtime,
	format KeyFormat,
	keyData goja.Value,
	normalizedAlgorithm RsaHashedImportParams,
	extractable bool,
	usages []CryptoKeyUsage,
) (goja.Value, error) {
	var result goja.Value
	var err error

	switch format {
	case SpkiKeyFormat:
		result, err = importRSAKeyFromSpki(rt, keyData, normalizedAlgorithm, extractable, usages)
	case Pkcs8KeyFormat:
		result, err = importRSAKeyFromPkcs8(rt, keyData, normalizedAlgorithm, extractable, usages)
	case JwkKeyFormat:
		result, err = importRSAKeyFromJwk(rt, keyData, normalizedAlgorithm, extractable, usages)
	default:
		break
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

//nolint:unused
func importRSAKeyFromSpki(
	rt *goja.Runtime,
	keyData goja.Value,
	normalizedAlgorithm RsaHashedImportParams,
	extractable bool,
	usages []CryptoKeyUsage,
) (goja.Value, error) {
	// // 1.
	// var data []byte
	// err := rt.ExportTo(keyData, &data)
	// if err != nil {
	// 	return nil, NewError(0, DataError, "could not export key data")
	// }

	// // 2.1.
	// if !ContainsOnly(usages, VerifyCryptoKeyUsage) {
	// 	return nil, NewError(0, SyntaxError, "invalid key usages")
	// }

	// // This works assuming the x509.ParsePKIXPublicKey function implements
	// // the steps 2.2. to 2.7.

	// // 2.8.
	// k, err := x509.ParsePKIXPublicKey(data)
	// if err != nil {
	// 	// 2.9.
	// 	return nil, NewError(0, DataError, "could not parse key data")
	// }
	// pubKey := k.(*rsa.PublicKey)

	// // 2.10.
	// key := CryptoKey[*rsa.PublicKey]{
	// 	handle: pubKey,
	// }

	// // 2.11.
	// key.Type = PublicCryptoKeyType

	// return rt.ToValue(key), nil
	return nil, NewError(0, OperationError, "importing RSA keys from SPKI is not supported")
}

//nolint:unused
func importRSAKeyFromPkcs8(
	rt *goja.Runtime,
	keyData goja.Value,
	normalizedAlgorithm RsaHashedImportParams,
	extractable bool,
	usages []CryptoKeyUsage,
) (goja.Value, error) {
	// // 1.
	// var data []byte
	// err := rt.ExportTo(keyData, &data)
	// if err != nil {
	// 	return nil, NewError(0, DataError, "could not export key data")
	// }

	// // 2.1.
	// if !ContainsOnly(usages, SignCryptoKeyUsage) {
	// 	return nil, NewError(0, SyntaxError, "invalid key usages")
	// }

	// // 2.2.
	// k, err := x509.ParsePKCS8PrivateKey(data)
	// if err != nil {
	// 	// 2.3.
	// 	return nil, NewError(0, DataError, "could not parse key data")
	// }
	// privKey := k.(*rsa.PrivateKey)

	// // 2.10.
	// key := CryptoKey[*rsa.PrivateKey]{
	// 	handle: privKey,
	// }

	// // 2.11.
	// key.Type = PrivateCryptoKeyType

	// return rt.ToValue(key), nil

	return nil, NewError(0, NotSupportedError, "importing RSA keys from PKCS#8 is not supported")
}

//nolint:funlen,unused
func importRSAKeyFromJwk(
	rt *goja.Runtime,
	keyData goja.Value,
	normalizedAlgorithm RsaHashedImportParams,
	extractable bool,
	usages []CryptoKeyUsage,
) (goja.Value, error) {
	var result goja.Value

	// // 2.1.
	// var jwk JSONWebKey
	// err := rt.ExportTo(keyData, &jwk)
	// if err != nil {
	// 	return nil, NewError(0, DataError, "could not import data as JSON Web Key")
	// }

	// // 2.2.
	// if jwk.D != "" && jwk.D != SignCryptoKeyUsage || jwk.D == "" && !Contains(usages, VerifyCryptoKeyUsage) {
	// 	return nil, NewError(0, SyntaxError, "invalid key usages")
	// }

	// // 2.3.
	// if jwk.KeyType != "RSA" {
	// 	return nil, NewError(0, DataError, "invalid key type")
	// }

	// // 2.4.
	// if len(usages) > 0 && jwk.Use != "" && strings.EqualFold(jwk.Use, "sig") {
	// 	return nil, NewError(0, DataError, "invalid key usages")
	// }

	// // 2.5.
	// if jwk.KeyOps != nil {
	// 	for _, usage := range usages {
	// 		if !Contains(jwk.KeyOps, usage) {
	// 			return nil, NewError(0, DataError, "invalid key usage")
	// 		}
	// 	}
	// }

	// // 2.6.
	// if !jwk.Extractable && extractable {
	// 	return nil, NewError(0, DataError, "invalid key extractability")
	// }

	// // 2.7.
	// var hash HashAlgorithmIdentifier

	// // 2.8.
	// // FIXME: jwk.Algorithm should be a pointer to account for the "alg" field not being present.
	// switch jwk.Algorithm {
	// case "":
	// 	break
	// case "RS1":
	// 	hash = Sha1
	// case "RS256":
	// 	hash = Sha256
	// case "RS384":
	// 	hash = Sha384
	// case "RS512":
	// 	hash = Sha512
	// default:
	// 	return nil, NewError(0, DataError, "invalid key algorithm")
	// }

	// // 2.9.
	// if hash != "" {
	// 	// 2.9.1.
	// 	normalizedHash, err := NormalizeAlgorithm(hash, OperationIdentifierDigest)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	// 2.9.2.
	// 	if normalizedHash != normalizedAlgorithm.Hash {
	// 		return nil, NewError(0, DataError, "invalid key algorithm")
	// 	}
	// }

	// // 2.10.
	// if jwk.D != "" {
	// 	// TODO: implement this.
	// }

	// TODO: implement this.
	return result, NewError(0, NotSupportedError, "importing RSA keys from JWK is not yet supported")
}
