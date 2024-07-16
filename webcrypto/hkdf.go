package webcrypto

import "github.com/grafana/sobek"

func newHKDFKeyDeriveParams(rt *sobek.Runtime, normalized Algorithm, params sobek.Value) (*HKDFParams, error) {
	//TODO: add implmentation
	return nil, nil
}

func (h HKDFParams) DeriveKey() (CryptoKeyGenerationResult, error){
	return nil, nil
}
