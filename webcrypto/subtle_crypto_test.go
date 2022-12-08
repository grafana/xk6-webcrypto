package webcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FIXME: Add failure tests.
func TestSubtleCryptoGenerateKey(t *testing.T) {
	t.Parallel()

	// We compile the helpers script content into a goja Program
	helpersProgram, err := CompileFile("../testdata/scripts", "helpers.js")
	require.NoError(t, err)

	// We compile the assert script content into a goja Program
	// We compile the helpers script content into a goja Program
	assertProgram, err := CompileFile("../testdata/scripts", "assert.js")
	require.NoError(t, err)

	t.Run("successes", func(t *testing.T) {
		t.Parallel()
		ts := newTestSetup(t)

		gotScriptErr := ts.ev.Start(func() error {
			// FIXME: move compiling to the test setup
			// We execute the helpers script in the runtime which effectively
			// loads the helper functions into the runtime
			_, err = ts.rt.RunProgram(helpersProgram)
			require.NoError(t, err)

			// We execute the helpers script in the runtime which effectively
			// loads the helper functions into the runtime
			_, err = ts.rt.RunProgram(assertProgram)
			require.NoError(t, err)

			// Run the test script. Note that
			_, err = ts.rt.RunString(`
				var subtle = crypto.subtle;

				var testVectors = [ // Parameters that should work for generateKey
					{name: "AES-CTR",  resultType: "CryptoKey", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "AES-CBC",  resultType: "CryptoKey", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "AES-GCM",  resultType: "CryptoKey", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "AES-KW",   resultType: "CryptoKey", usages: ["wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "HMAC",     resultType: "CryptoKey", usages: ["sign", "verify"], mandatoryUsages: []},
					{name: "RSASSA-PKCS1-v1_5", resultType: "CryptoKeyPair", usages: ["sign", "verify"], mandatoryUsages: ["sign"]},
					{name: "RSA-PSS",  resultType: "CryptoKeyPair", usages: ["sign", "verify"], mandatoryUsages: ["sign"]},
					{name: "RSA-OAEP", resultType: "CryptoKeyPair", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: ["decrypt", "unwrapKey"]},
					{name: "ECDSA",    resultType: "CryptoKeyPair", usages: ["sign", "verify"], mandatoryUsages: ["sign"]},
				];

				testVectors = testVectors.filter((vector) => {
					allNameVariants(vector.name).forEach((name) => {
						allAlgorithmSpecifiersFor(name).forEach((algorithm) => {
							allValidUsages(vector.usages, false, vector.mandatoryUsages).forEach((usages) => {
								[false, true].forEach((extractable) => {

									subtle.generateKey(algorithm, extractable, usages).then(
										(result) => {
											if (vector.resultType === "CryptoKeyPair") {
												assert_goodCryptoKey(result.privateKey, algorithm, extractable, usages, "private");
												assert_goodCryptoKey(result.publicKey, algorithm, extractable, usages, "public");
											} else {
												assert_goodCryptoKey(result, algorithm, extractable, usages, "secret");
											}
										},
										(err) => {
											throw "Threw an unexpected error: " + err
										}
									)

								})
							})
						})
					})
				})

				function assert_goodCryptoKey(key, algorithm, extractable, usages, kind) {
					var correctUsages = [];

					// Defined in helpers.js
					var registeredAlgorithmName;
					registeredAlgorithmNames.forEach(function(name) {
						if (name.toUpperCase() === algorithm.name.toUpperCase()) {
							registeredAlgorithmName = name;
						}
					});

					assert_equals(key.type, kind, "is a " + kind + " key");
					if (key.type === "public") {
						extractable = true;  // public keys are always extractable
					}

					assert_equals(key.extractable, extractable, "extractability is correct");
					assert_equals(key.algorithm.name, registeredAlgorithmName, "algorithm name is correct");

					if (key.algorithm.name.toUpperCase() === "HMAC" && algorithm.length === undefined) {
						switch (key.algorithm.hash.name.toUpperCase()) {
						case "SHA-1":
						case "SHA-256":
							assert_equals(key.algorithm.length, 512, "correct length");
							break;
						case "SHA-384":
						case "SHA-512":
							assert_equals(key.algorithm.length, 1024, "correct length");
							break;
						}
					} else {
						assert_equals(key.algorithm.length, algorithm.length, "correct length");
					}

					// if (registeredAlgorithmName === "HMAC" ||
					// 	registeredAlgorithmName === "RSASSA-PKCS1-v1_5" ||
					// 	registeredAlgorithmName === "RSA-PSS") {
					if ([ "HMAC", "RSASSA-PKCS1-v1_5", "RSA-PSS" ].includes(registeredAlgorithmName)) {
						assert_equals(key.algorithm.hash.name.toUpperCase(), algorithm.hash.toUpperCase(), "correct hash function");
					}

					// usages is expected to be provided for a key pair, but we are checking
					// only a single key. The publicKey and privateKey portions of a key pair
					// recognize only some of the usages appropriate for a key pair.
					if (key.type === "public") {
						["encrypt", "verify", "wrapKey"].forEach(function(usage) {
							if (usages.includes(usage)) {
								correctUsages.push(usage);
							}
						});
					} else if (key.type === "private") {
						["decrypt", "sign", "unwrapKey", "deriveKey", "deriveBits"].forEach(function(usage) {
							if (usages.includes(usage)) {
								correctUsages.push(usage);
							}
						});
					} else {
						correctUsages = usages;
					}

					assert_equals((typeof key.usages), "object", key.type + " key usages is an object");
					assert_not_equals(key.usages, null, key.type + " key usages is not null");

					var usageCount = 0;
					key.usages.forEach(function(usage) {
						usageCount += 1
						assert_in_array(usage, correctUsages, "has " + usage + " usage");
					})

					assert_equals(key.usages.length, usageCount, "usages property is correct");
				}
			`)

			return err
		})

		assert.NoError(t, gotScriptErr)
	})

	t.Run("failures", func(t *testing.T) {
		t.Parallel()

		ts := newTestSetup(t)

		gotScriptErr := ts.ev.Start(func() error {
			// FIXME: move compiling to the test setup
			// We execute the helpers script in the runtime which effectively
			// loads the helper functions into the runtime
			_, err = ts.rt.RunProgram(helpersProgram)
			require.NoError(t, err)

			// We execute the helpers script in the runtime which effectively
			// loads the helper functions into the runtime
			_, err = ts.rt.RunProgram(assertProgram)
			require.NoError(t, err)

			// Run the test script. Note that
			_, err = ts.rt.RunString(`
				var subtle = crypto.subtle;

				var allTestVectors = [ // Parameters that should work for generateKey
					{name: "AES-CTR",  resultType: "CryptoKey", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "AES-CBC",  resultType: "CryptoKey", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "AES-GCM",  resultType: "CryptoKey", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "AES-KW",   resultType: "CryptoKey", usages: ["wrapKey", "unwrapKey"], mandatoryUsages: []},
					{name: "HMAC",     resultType: "CryptoKey", usages: ["sign", "verify"], mandatoryUsages: []},
					{name: "RSASSA-PKCS1-v1_5", resultType: "CryptoKeyPair", usages: ["sign", "verify"], mandatoryUsages: ["sign"]},
					{name: "RSA-PSS",  resultType: "CryptoKeyPair", usages: ["sign", "verify"], mandatoryUsages: ["sign"]},
					{name: "RSA-OAEP", resultType: "CryptoKeyPair", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"], mandatoryUsages: ["decrypt", "unwrapKey"]},
					{name: "ECDSA",    resultType: "CryptoKeyPair", usages: ["sign", "verify"], mandatoryUsages: ["sign"]},

					// {name: "ECDH",     resultType: "CryptoKeyPair", usages: ["deriveKey", "deriveBits"], mandatoryUsages: ["deriveKey", "deriveBits"]},
				];

				algorithmNames = allTestVectors.map(function(v) { return v.name; });

				var testVectors = [];
				if (algorithmNames && !Array.isArray(algorithmNames)) {
					algorithmNames = [algorithmNames];
				};
				allTestVectors.forEach(function(vector) {
					if (!algorithmNames || algorithmNames.includes(vector.name)) {
						testVectors.push(vector);
					}
				});

				function testError(algorithm, extractable, usages, expectedError, testTag) {
					subtle.generateKey(algorithm, extractable, usages)
						.then(
							(result) => { assert_unreached("operation succeeded, but should not have") },
							(err) => {
								assert_equals(err.name, expectedError, testTag + " not supported");
							}
						)
				}

				// Given an algorithm name, create several invalid parameters.
				function badAlgorithmPropertySpecifiersFor(algorithmName) {
					var results = [];
			
					if (algorithmName.toUpperCase().substring(0, 3) === "AES") {
						// Specifier properties are name and length
						[64, 127, 129, 255, 257, 512].forEach(function(length) {
							results.push({name: algorithmName, length: length});
						});
					} else if (algorithmName.toUpperCase().substring(0, 3) === "RSA") {
						[new Uint8Array([1]), new Uint8Array([1,0,0])].forEach(function(publicExponent) {
							results.push({name: algorithmName, hash: "SHA-256", modulusLength: 1024, publicExponent: publicExponent});
						});
					} else if (algorithmName.toUpperCase().substring(0, 2) === "EC") {
						["P-512", "Curve25519"].forEach(function(curveName) {
							results.push({name: algorithmName, namedCurve: curveName});
						});
					}
			
					return results;
				}

				// Algorithm normalization should fail with "Not supported"
				var badAlgorithmNames = [
					"AES",
					{name: "AES"},
					{name: "AES", length: 128},
					{name: "AES-CMAC", length: 128},
					{name: "AES-CFB", length: 128},
					{name: "HMAC", hash: "MD5"},
					{name: "RSA", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1])},
					{name: "RSA-PSS", hash: "SHA", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1])},
					{name: "EC", namedCurve: "P521"}
				];
			
				// Algorithm normalization failures should be found first
				// - all other parameters can be good or bad, should fail
				//   due to NotSupportedError.
				badAlgorithmNames.forEach(function(algorithm) {
					allValidUsages(["decrypt", "sign", "deriveBits"], true, []) // Small search space, shouldn't matter because should fail before used
						.forEach(function(usages) {
							[false, true, "RED", 7].forEach(function(extractable){
									
								testError(algorithm, extractable, usages, "NotSupportedError", "Bad algorithm");
							
							});
						});
				});

				// Algorithms normalize okay, but usages bad (though not empty).
				// It shouldn't matter what other extractable is. Should fail
				// due to SyntaxError
				testVectors.forEach(function(vector) {
					var name = vector.name;
			
					allAlgorithmSpecifiersFor(name).forEach(function(algorithm) {
						invalidUsages(vector.usages, vector.mandatoryUsages).forEach(function(usages) {
							[true].forEach(function(extractable) {

								testError(algorithm, extractable, usages, "SyntaxError", "Bad usages");
							
							});
						});
					});
				});

				// TODO: those tests are not reliable, and they fail on scenarios that
				// are not described by the specs.

				// // Other algorithm properties should be checked next, so try good
				// // algorithm names and usages, but bad algorithm properties next.
				// // - Special case: normally bad usage [] isn't checked until after properties,
				// //   so it's included in this test case. It should NOT cause an error.
				// testVectors.forEach(function(vector) {
				// 	var name = vector.name;
				// 	badAlgorithmPropertySpecifiersFor(name).forEach(function(algorithm) {
				// 		allValidUsages(vector.usages, true, vector.mandatoryUsages)
				// 		.forEach(function(usages) {
				// 			[false, true].forEach(function(extractable) {

				// 				if (name.substring(0,2) === "EC") {
				// 					testError(algorithm, extractable, usages, "NotSupportedError", "Bad algorithm property");
				// 				} else if (name === "RSA-OAEP") {
				// 					testError(algorithm, extractable, usages, "SyntaxError", "Bad algorithm property");
				// 				} else {
				// 					testError(algorithm, extractable, usages, "OperationError", "Bad algorithm property");
				// 				}

				// 			});
				// 		});
				// 	});
				// });



				// The last thing that should be checked is an empty usages (for secret keys).
				testVectors.forEach(function(vector) {
					var name = vector.name;
			
					allAlgorithmSpecifiersFor(name).forEach(function(algorithm) {
						var usages = [];
						[false, true].forEach(function(extractable) {
							testError(algorithm, extractable, usages, "SyntaxError", "Empty usages");
						});
					});
				});
			`)

			return err
		})

		assert.NoError(t, gotScriptErr)
	})
}
