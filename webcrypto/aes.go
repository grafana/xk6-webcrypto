package webcrypto

import (
	"crypto/rand"
)

// AesKeyGenParams represents the object that should be passed as
// the algorithm parameter into `SubtleCrypto.generateKey`, when generating
// an AES key: that is, when the algorithm is identified as any
// of AES-CBC, AES-CTR, AES-GCM, or AES-KW.
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#aes-keygen-params
type AesKeyGenParams struct {
	Algorithm

	// The length, in bits, of the key.
	Length int64 `json:"length"`
}

// GenerateKey generates a new AES key.
func (akgp *AesKeyGenParams) GenerateKey(
	extractable bool,
	keyUsages []CryptoKeyUsage,
) (*CryptoKey, error) {
	for _, usage := range keyUsages {
		switch usage {
		case WrapKeyCryptoKeyUsage, UnwrapKeyCryptoKeyUsage:
			continue
		case EncryptCryptoKeyUsage, DecryptCryptoKeyUsage:
			// At the time of writing, the go standard library [doesn't
			// support AES-KW](https://github.com/golang/go/issues/27599), we
			// might want to revisit this in the future.
			if akgp.Algorithm.Name != AESKw {
				continue
			}

			return nil, NewError(0, SyntaxError, "invalid key usage")
		default:
			return nil, NewError(0, SyntaxError, "invalid key usage")
		}
	}

	if akgp.Length != 128 && akgp.Length != 192 && akgp.Length != 256 {
		return nil, NewError(0, OperationError, "invalid key length")
	}

	randomKey := make([]byte, akgp.Length/8)
	if _, err := rand.Read(randomKey); err != nil {
		// 4.
		return nil, NewError(0, OperationError, "could not generate random key")
	}

	// 5. 6. 7. 8. 9.
	key := CryptoKey{}
	key.Type = SecretCryptoKeyType
	key.Algorithm = AesKeyAlgorithm{
		Algorithm: akgp.Algorithm,
		Length:    akgp.Length,
	}

	// 10.
	key.Extractable = extractable

	// 11.
	key.Usages = keyUsages

	// Set key handle to our random key.
	key.handle = randomKey

	// 12.
	return &key, nil
}

// AesKeyAlgorithm is the algorithm for AES keys as defined in the [specification].
//
// [specification]: https://www.w3.org/TR/WebCryptoAPI/#dfn-AesKeyAlgorithm
type AesKeyAlgorithm struct {
	Algorithm

	Length int64 `json:"length"`
}
