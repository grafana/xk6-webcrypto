// Package webcrypto exports the webcrypto API.
package webcrypto

import (
	"github.com/dop251/goja"
	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
)

type (
	// RootModule is the global module instance that will create Client
	// instances for each VU.
	RootModule struct{}

	// ModuleInstance represents an instance of the JS module.
	ModuleInstance struct {
		vu modules.VU

		*Crypto
	}
)

// Ensure the interfaces are implemented correctly
var (
	_ modules.Instance = &ModuleInstance{}
	_ modules.Module   = &RootModule{}
)

// New returns a pointer to a new RootModule instance
func New() *RootModule {
	return &RootModule{}
}

// NewModuleInstance implements the modules.Module interface and returns
// a new instance for each VU.
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	rt := vu.Runtime()

	ck := &CryptoKey{
		obj: rt.NewObject(),
	}

	c := &Crypto{
		obj: rt.NewObject(),
		vu:  vu,
		Subtle: &SubtleCrypto{
			vu: vu,
		},
		CryptoKey: ck,
	}

	must(rt, c.obj.DefineDataProperty(
		"subtle", rt.ToValue(c.Subtle), goja.FLAG_TRUE, goja.FLAG_FALSE, goja.FLAG_TRUE))
	must(rt, c.obj.DefineDataProperty(
		"CryptoKey", rt.ToValue(c.CryptoKey), goja.FLAG_TRUE, goja.FLAG_FALSE, goja.FLAG_TRUE))

	must(rt, c.obj.DefineDataProperty(
		"getRandomValues", rt.ToValue(c.GetRandomValues), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_TRUE))
	must(rt, c.obj.DefineDataProperty(
		"randomUUID", rt.ToValue(c.RandomUUID), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_TRUE))

	return &ModuleInstance{
		vu:     vu,
		Crypto: c,
	}
}

// Exports implements the modules.Instance interface and returns
// the exports of the JS module.
func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{Named: map[string]interface{}{
		"crypto": mi.Crypto.obj,
	}}
}

// must is a small helper that will panic if err is not nil.
func must(rt *goja.Runtime, err error) {
	if err != nil {
		common.Throw(rt, err)
	}
}
