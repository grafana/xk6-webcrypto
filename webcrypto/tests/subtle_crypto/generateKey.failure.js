var subtle = crypto.subtle;

var allTestVectors = [
  // Parameters that should work for generateKey
  {
    name: "AES-CTR",
    resultType: "CryptoKey",
    usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    mandatoryUsages: [],
  },
  {
    name: "AES-CBC",
    resultType: "CryptoKey",
    usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    mandatoryUsages: [],
  },
  {
    name: "AES-GCM",
    resultType: "CryptoKey",
    usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    mandatoryUsages: [],
  },
  {
    name: "AES-KW",
    resultType: "CryptoKey",
    usages: ["wrapKey", "unwrapKey"],
    mandatoryUsages: [],
  },
  {
    name: "HMAC",
    resultType: "CryptoKey",
    usages: ["sign", "verify"],
    mandatoryUsages: [],
  },
  {
    name: "RSASSA-PKCS1-v1_5",
    resultType: "CryptoKeyPair",
    usages: ["sign", "verify"],
    mandatoryUsages: ["sign"],
  },
  {
    name: "RSA-PSS",
    resultType: "CryptoKeyPair",
    usages: ["sign", "verify"],
    mandatoryUsages: ["sign"],
  },
  {
    name: "RSA-OAEP",
    resultType: "CryptoKeyPair",
    usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    mandatoryUsages: ["decrypt", "unwrapKey"],
  },
  {
    name: "ECDSA",
    resultType: "CryptoKeyPair",
    usages: ["sign", "verify"],
    mandatoryUsages: ["sign"],
  },
];

algorithmNames = allTestVectors.map(function (v) {
  return v.name;
});

var testVectors = [];
if (algorithmNames && !Array.isArray(algorithmNames)) {
  algorithmNames = [algorithmNames];
}

allTestVectors.forEach(function (vector) {
  if (!algorithmNames || algorithmNames.includes(vector.name)) {
    testVectors.push(vector);
  }
});

function testError(algorithm, extractable, usages, expectedError, testTag) {
  subtle.generateKey(algorithm, extractable, usages).then(
    (result) => {
      assert_unreached("operation succeeded, but should not have");
    },
    (err) => {
      assert_equals(err.name, expectedError, testTag + " not supported");
    }
  );
}

// Given an algorithm name, create several invalid parameters.
function badAlgorithmPropertySpecifiersFor(algorithmName) {
  var results = [];

  if (algorithmName.toUpperCase().substring(0, 3) === "AES") {
    // Specifier properties are name and length
    [64, 127, 129, 255, 257, 512].forEach(function (length) {
      results.push({ name: algorithmName, length: length });
    });
  } else if (algorithmName.toUpperCase().substring(0, 3) === "RSA") {
    [new Uint8Array([1]), new Uint8Array([1, 0, 0])].forEach(function (
      publicExponent
    ) {
      results.push({
        name: algorithmName,
        hash: "SHA-256",
        modulusLength: 1024,
        publicExponent: publicExponent,
      });
    });
  } else if (algorithmName.toUpperCase().substring(0, 2) === "EC") {
    ["P-512", "Curve25519"].forEach(function (curveName) {
      results.push({ name: algorithmName, namedCurve: curveName });
    });
  }

  return results;
}

// Algorithm normalization should fail with "Not supported"
var badAlgorithmNames = [
  "AES",
  { name: "AES" },
  { name: "AES", length: 128 },
  { name: "AES-CMAC", length: 128 },
  { name: "AES-CFB", length: 128 },
  { name: "HMAC", hash: "MD5" },
  {
    name: "RSA",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  },
  {
    name: "RSA-PSS",
    hash: "SHA",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  },
  { name: "EC", namedCurve: "P521" },
];

// Algorithm normalization failures should be found first
// - all other parameters can be good or bad, should fail
//   due to NotSupportedError.
badAlgorithmNames.forEach(function (algorithm) {
  allValidUsages(["decrypt", "sign", "deriveBits"], true, []) // Small search space, shouldn't matter because should fail before used
    .forEach(function (usages) {
      [false, true, "RED", 7].forEach(function (extractable) {
        testError(
          algorithm,
          extractable,
          usages,
          "NotSupportedError",
          "Bad algorithm"
        );
      });
    });
});

// Algorithms normalize okay, but usages bad (though not empty).
// It shouldn't matter what other extractable is. Should fail
// due to SyntaxError
testVectors.forEach(function (vector) {
  var name = vector.name;

  allAlgorithmSpecifiersFor(name).forEach(function (algorithm) {
    invalidUsages(vector.usages, vector.mandatoryUsages).forEach(function (
      usages
    ) {
      [true].forEach(function (extractable) {
        testError(algorithm, extractable, usages, "SyntaxError", "Bad usages");
      });
    });
  });
});

// Other algorithm properties should be checked next, so try good
// algorithm names and usages, but bad algorithm properties next.
// - Special case: normally bad usage [] isn't checked until after properties,
//   so it's included in this test case. It should NOT cause an error.
testVectors.forEach(function (vector) {
  var name = vector.name;
  badAlgorithmPropertySpecifiersFor(name).forEach(function (algorithm) {
    allValidUsages(vector.usages, true, vector.mandatoryUsages).forEach(
      function (usages) {
        [false, true].forEach(function (extractable) {
          if (name.substring(0, 2) === "EC") {
            testError(
              algorithm,
              extractable,
              usages,
              "NotSupportedError",
              "Bad algorithm property"
            );
          } else {
            testError(
              algorithm,
              extractable,
              usages,
              "OperationError",
              "Bad algorithm property"
            );
          }
        });
      }
    );
  });
});

// The last thing that should be checked is an empty usages (for secret keys).
testVectors.forEach(function (vector) {
  var name = vector.name;

  allAlgorithmSpecifiersFor(name).forEach(function (algorithm) {
    var usages = [];
    [false, true].forEach(function (extractable) {
      testError(algorithm, extractable, usages, "SyntaxError", "Empty usages");
    });
  });
});
