package webcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubtleCryptoGenerateKey(t *testing.T) {
	t.Parallel()

	t.Run("successes", func(t *testing.T) {
		t.Parallel()

		ts := newTestSetup(t)

		gotScriptErr := ts.ev.Start(func() error {
			successCasesProgram, err := CompileFile("./tests/subtle_crypto", "generateKey.success.js")
			require.NoError(t, err)

			_, err = ts.rt.RunProgram(successCasesProgram)
			return err
		})

		assert.NoError(t, gotScriptErr)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		ts := newTestSetup(t)

		gotScriptErr := ts.ev.Start(func() error {
			failureCasesProgram, err := CompileFile("./tests/subtle_crypto", "generateKey.failure.js")
			require.NoError(t, err)

			_, err = ts.rt.RunProgram(failureCasesProgram)
			require.NoError(t, err)

			return err
		})

		assert.NoError(t, gotScriptErr)
	})
}

func TestSubtleCryptoEncrypt(t *testing.T) {
	t.Parallel()

	t.Run("aes cbc", func(t *testing.T) {
		t.Parallel()

		ts := newTestSetup(t)

		gotScriptErr := ts.ev.Start(func() error {
			cbcVectors, err := CompileFile("./tests/subtle_crypto/encrypt_decrypt", "aes_cbc_vectors.js")
			require.NoError(t, err)

			_, err = ts.rt.RunProgram(cbcVectors)
			require.NoError(t, err)

			testProgram, err := CompileFile("./tests/subtle_crypto/encrypt_decrypt", "aes.js")
			require.NoError(t, err)

			_, err = ts.rt.RunProgram(testProgram)

			return err
		})

		assert.NoError(t, gotScriptErr)
	})
}
