package webcrypto

type KeyGenerator interface {
	GenerateKey(extractable bool, keyUsages []CryptoKeyUsage) (interface{}, error)
}
