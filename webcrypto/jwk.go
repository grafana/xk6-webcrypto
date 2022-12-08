package webcrypto

// JSONWebKey represents a [JSON Web Key].
//
// [JSON Web Key]: https://www.w3.org/TR/WebCryptoAPI/#JsonWebKey-dictionary
type JSONWebKey struct {
	// Kty holds the key type.
	KeyType string `json:"kty"`

	// Use holds the [intended use] of the key.
	// [intended use]: https://www.rfc-editor.org/rfc/rfc7517#section-4.2
	Use JSONWebKeyUse `json:"use"`

	// KeyOps holds the [operations] for which the key is intended to be used.
	// Note that the "key_ops" values intentionally match the "KeyUsage"
	// values defined in the Web [Cryptography API].
	// [Web Cryptography API]: https://www.w3.org/TR/WebCryptoAPI
	KeyOps []CryptoKeyUsage `json:"key_ops"`

	// FIXME: should be optional? ("if not present")
	// Alg holds the algorithm intended for use with the key.
	Algorithm string `json:"alg"`

	// FIXME: should be optional? ("if not present")
	// Ext indicates whether the key is extractable.
	Extractable bool `json:"ext"`

	// Crv holds the elliptic curve used with the key.
	Crv string

	// X holds the X coordinate for the elliptic curve point.
	X string

	// Y holds the Y coordinate for the elliptic curve point.
	Y string

	// FIXME: should be optional? ("if not present")
	// D holds the private key value.
	D string

	// N holds the modulus value for the RSA public key.
	N string

	// E holds the exponent value for the RSA public key.
	E string

	// P holds the first prime factor value for the RSA private key.
	P string

	// Q holds the second prime factor value for the RSA private key.
	Q string

	// DP holds the first factor CRT exponent value for the RSA private key.
	Dp string

	// DQ holds the second factor CRT exponent value for the RSA private key.
	Dq string

	// QI holds the first CRT coefficient value for the RSA private key.
	Qi string

	// Oth holds the other primes info for the RSA private key.
	Oth RsaOtherPrimesInfo

	// K holds the symmetric key value.
	K string
}

// RsaOtherPrimesInfo represents the [primes info] for a RSA private key.
//
// [primes info]: https://www.w3.org/TR/WebCryptoAPI/#JsonWebKey-dictionary
type RsaOtherPrimesInfo struct {
	// R holds the prime factor value.
	R string

	// D holds the factor CRT exponent value.
	D string

	// T holds the factor CRT coefficient value.
	T string
}

// JSONWebKeyUse represents the [intended use] of a JSON Web Key.
//
// JSonWebKeyUse represents the [intended use] of a JSON Web Key.
// [intended use]:
type JSONWebKeyUse = string

const (
	// JSONWebKeySignatureUse represents the signature use.
	JSONWebKeySignatureUse = "sig"

	// JSONWebKeyEncryptionUse represents the encryption use.
	JSONWebKeyEncryptionUse = "enc"
)
