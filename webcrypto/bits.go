package webcrypto

type bitsDeriver func(CryptoKey, CryptoKey) ([]byte, error)

func newBitsDeriver(algName string) (bitsDeriver, error) {
	switch algName {
	case ECDH:
		return deriveBitsECDH, nil
	case PBKDF2:
		return deriveBitsPBKDF2, nil
	}

	return nil, NewError(NotSupportedError, "unsupported algorithm for derive bits: "+algName)
}
