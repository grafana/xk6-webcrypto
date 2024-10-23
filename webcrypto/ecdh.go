package webcrypto

import "github.com/grafana/sobek"

func newECDHDeriveParams(rt *sobek.Runtime, normalized Algorithm, params sobek.Value) (*ECDHKeyDeriveParams, error) {
	//TODO: add implmentation
	return nil, nil
}

func (e *ECDHKeyDeriveParams) DeriveKey() (CryptoKeyGenerationResult, error){
	return nil, nil
}
