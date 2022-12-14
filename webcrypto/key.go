package webcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
)

// CryptoKeyPair represents a key pair for an asymmetric cryptography algorithm, also known as
// a public-key algorithm.
//
// The Private, and Public generic type parameters define the underlying type holding the private,
// and public key, respectively.
type CryptoKeyPair[Private PrivateHandle, Public PublicHandle] struct {
	// PrivateKey holds the private key. For encryption and decryption algorithms,
	// this key is used to decrypt. For signing and verification algorithms it is used to sign.
	PrivateKey CryptoKey[Private] `json:"privateKey"`

	// PublicKey holds the public key. For encryption and decryption algorithms,
	// this key is used to encrypt. For signing and verification algorithms it is used to verify.
	PublicKey CryptoKey[Public] `json:"publicKey"`
}

// CryptoKey represents a cryptographic key obtained from one of the SubtleCrypto
// methods `SubtleCrypto.generateKey`, `SubtleCrypto.DeriveKey`, `SubtleCrypto.ImportKey`,
// or `SubtleCrypto.UnwrapKey`.
type CryptoKey[H KeyHandle] struct {
	// Type holds the type of the key.
	Type CryptoKeyType `json:"type"`

	// FIXME: should be private?
	// Extractable indicates whether or not the key may be extracted
	// using `SubtleCrypto.ExportKey` or `SubtleCrypto.WrapKey`.
	//
	// If the value is `true`, the key may be extracted.
	// If the value is `false`, the key may not be extracted, and
	// `SubtleCrypto.exportKey` and `SubtleCrypto.wrapKey` will fail.
	Extractable bool `json:"extractable"`

	// FIXME: should be private?
	// Algorithm holds the algorithm for which this key can be used
	// and any associated extra parameters.
	//
	// The value of this property is an object that is specific to the
	// algorithm used to generate the key. Possible values should be castable
	// to the following types:
	//   - AESKeyGenParams
	//   - RSAHashedKeyGenParams
	//   - ECKeyGenParams
	//   - HMACKeyGenParams
	Algorithm interface{} `json:"algorithm"`

	// FIXME: should be private?
	// Usages indicates what can be done with the key.
	Usages []CryptoKeyUsage `json:"usages"`

	// handle is an internal slot, holding the underlying key data.
	// See [specification](https://www.w3.org/TR/WebCryptoAPI/#dfnReturnLink-0).
	//nolint:unused
	handle H
}

// KeyHandle is an interface that represents a cryptographic key handle (data).
// It is meant to be used as a generic type parameter for CryptoKey.
type KeyHandle interface {
	SecretHandle | PrivateHandle | PublicHandle
}

// SecretHandle is an interface that represents a secret key.
// It is meant to be used as a generic type parameter for CryptoKey.
type SecretHandle interface {
	[]byte
}

// PrivateHandle is an interface that represents a private key.
// It is meant to be used as a generic type parameter for CryptoKeyPair.
type PrivateHandle interface {
	crypto.PrivateKey | rsa.PrivateKey | ecdsa.PrivateKey
}

// PublicHandle is an interface that represents a public key.
// It is meant to be used as a generic type parameter for CryptoKeyPair.
type PublicHandle interface {
	crypto.PublicKey | rsa.PublicKey | ecdsa.PublicKey
}

// CryptoKeyGenerator is an interface that represents a cryptographic key generator.
// It is meant to be implemented by the various key generation algorithms.
type CryptoKeyGenerator[H SecretHandle] interface {
	GenerateKey(extractable bool, keyUsages []CryptoKeyUsage) (*CryptoKey[H], error)
}

// CryptoKeyPairGenerator is an interface that represents a cryptographic key pair generator.
// It is meant to be implemented by the various key pair generation algorithms.
type CryptoKeyPairGenerator[Private PrivateHandle, Public PublicHandle] interface {
	GenerateKeyPair(extractable bool, keyUsages []CryptoKeyUsage) (*CryptoKeyPair[Private, Public], error)
}

// KeyAlgorithm specifies the algorithm for a key.
type KeyAlgorithm struct {
	// Name of the algorithm.
	Name AlgorithmIdentifier `json:"name"`
}

// CryptoKeyType represents the type of a key.
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string by goja.
type CryptoKeyType = string

const (
	// SecretCryptoKeyType carries the information that a key is a secret key
	// to use with a symmetric algorithm.
	SecretCryptoKeyType CryptoKeyType = "secret"

	// PrivateCryptoKeyType carries the information that a key is the private half
	// of an asymmetric key pair.
	PrivateCryptoKeyType CryptoKeyType = "private"

	// PublicCryptoKeyType carries the information that a key is the public half
	// of an asymmetric key pair.
	PublicCryptoKeyType CryptoKeyType = "public"
)

// CryptoKeyUsage represents the usage of a key.
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string by goja.
type CryptoKeyUsage = string

const (
	// EncryptCryptoKeyUsage indicates that the key may be used to encrypt messages.
	EncryptCryptoKeyUsage CryptoKeyUsage = "encrypt"

	// DecryptCryptoKeyUsage indicates that the key may be used to decrypt messages.
	DecryptCryptoKeyUsage CryptoKeyUsage = "decrypt"

	// SignCryptoKeyUsage indicates that the key may be used to sign messages.
	SignCryptoKeyUsage CryptoKeyUsage = "sign"

	// VerifyCryptoKeyUsage indicates that the key may be used to verify signatures.
	VerifyCryptoKeyUsage CryptoKeyUsage = "verify"

	// DeriveKeyCryptoKeyUsage indicates that the key may be used to derive a new key.
	DeriveKeyCryptoKeyUsage CryptoKeyUsage = "deriveKey"

	// DeriveBitsCryptoKeyUsage indicates that the key may be used to derive bits.
	DeriveBitsCryptoKeyUsage CryptoKeyUsage = "deriveBits"

	// WrapKeyCryptoKeyUsage indicates that the key may be used to wrap another key.
	WrapKeyCryptoKeyUsage CryptoKeyUsage = "wrapKey"

	// UnwrapKeyCryptoKeyUsage indicates that the key may be used to unwrap another key.
	UnwrapKeyCryptoKeyUsage CryptoKeyUsage = "unwrapKey"
)

// InferCryptoKeyUsages infers the key usages for a given algorithm and key type.
// It returns a slice of CryptoKeyUsage. If the algorithm is not supported, it returns nil.
// It proves useful in places where we need to set a CryptoKey usages slice, depending
// on the algorithm and key type.
//
// This function follows the matching described in each algorithm GenerateKey method's
// specification.
func InferCryptoKeyUsages(a AlgorithmIdentifier, t CryptoKeyType) []CryptoKeyUsage {
	switch t {
	case SecretCryptoKeyType:
		switch a {
		case AESCbc, AESCtr, AESGcm:
			return []CryptoKeyUsage{
				EncryptCryptoKeyUsage,
				DecryptCryptoKeyUsage,
				WrapKeyCryptoKeyUsage,
				UnwrapKeyCryptoKeyUsage,
			}
		case HMAC:
			return []CryptoKeyUsage{
				SignCryptoKeyUsage,
				VerifyCryptoKeyUsage,
			}
		}
	case PrivateCryptoKeyType:
		switch a {
		case ECDSA:
			return []CryptoKeyUsage{SignCryptoKeyUsage}
		case RSAOaep:
			return []CryptoKeyUsage{DecryptCryptoKeyUsage, UnwrapKeyCryptoKeyUsage}
		case RSAPss, RSASsaPkcs1v15:
			return []CryptoKeyUsage{SignCryptoKeyUsage}
		}
	case PublicCryptoKeyType:
		switch a {
		case ECDSA:
			return []CryptoKeyUsage{VerifyCryptoKeyUsage}
		case RSAOaep:
			return []CryptoKeyUsage{EncryptCryptoKeyUsage, WrapKeyCryptoKeyUsage}
		case RSAPss, RSASsaPkcs1v15:
			return []CryptoKeyUsage{VerifyCryptoKeyUsage}
		}
	}

	return nil
}

// KeyFormat represents the format of a CryptoKey.
//
// Note that it is defined as an alias of string, instead of a dedicated type,
// to ensure it is handled as a string by goja.
type KeyFormat = string

const (
	// RawKeyFormat indicates that the key is in raw format.
	RawKeyFormat KeyFormat = "raw"

	// Pkcs8KeyFormat indicates that the key is in PKCS#8 format.
	Pkcs8KeyFormat KeyFormat = "pkcs8"

	// SpkiKeyFormat indicates that the key is in SubjectPublicKeyInfo format.
	SpkiKeyFormat KeyFormat = "spki"

	// JwkKeyFormat indicates that the key is in JSON Web Key format.
	JwkKeyFormat KeyFormat = "jwk"
)

// KeyLength holds the length of the key, in bits.
//
// Note that it is defined as an alias of uint16, instead of a dedicated type,
// to ensure it is handled as a number by goja.
type KeyLength = uint16

const (
	// KeyLength128 represents a 128 bits key length.
	KeyLength128 KeyLength = 128

	// KeyLength192 represents a 192 bits key length.
	KeyLength192 KeyLength = 192

	// KeyLength256 represents a 256 bits key length.
	KeyLength256 KeyLength = 256

	// KeyLength384 represents a 384 bits key length.
	KeyLength384 KeyLength = 384

	// KeyLength512 represents a 512 bits key length.
	KeyLength512 KeyLength = 512
)
