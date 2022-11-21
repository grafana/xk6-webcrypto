var subtle = crypto.subtle;

var testVectors = [
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

testVectors = testVectors.filter((vector) => {
  allNameVariants(vector.name).forEach((name) => {
    allAlgorithmSpecifiersFor(name).forEach((algorithm) => {
      allValidUsages(vector.usages, false, vector.mandatoryUsages).forEach(
        (usages) => {
          [false, true].forEach((extractable) => {
            subtle.generateKey(algorithm, extractable, usages).then(
              (result) => {
                if (vector.resultType === "CryptoKeyPair") {
                  assert_goodCryptoKey(
                    result.privateKey,
                    algorithm,
                    extractable,
                    usages,
                    "private"
                  );
                  assert_goodCryptoKey(
                    result.publicKey,
                    algorithm,
                    extractable,
                    usages,
                    "public"
                  );
                } else {
                  assert_goodCryptoKey(
                    result,
                    algorithm,
                    extractable,
                    usages,
                    "secret"
                  );
                }
              },
              (err) => {
                throw "Threw an unexpected error: " + JSON.stringify(err);
              }
            );
          });
        }
      );
    });
  });
});

function assert_goodCryptoKey(key, algorithm, extractable, usages, kind) {
  var correctUsages = [];

  // Defined in helpers.js
  var registeredAlgorithmName;
  registeredAlgorithmNames.forEach(function (name) {
    if (name.toUpperCase() === algorithm.name.toUpperCase()) {
      registeredAlgorithmName = name;
    }
  });

  assert_equals(key.type, kind, "is a " + kind + " key");
  if (key.type === "public") {
    extractable = true; // public keys are always extractable
  }

  assert_equals(key.extractable, extractable, "extractability is correct");
  assert_equals(
    key.algorithm.name,
    registeredAlgorithmName,
    "algorithm name is correct"
  );

  if (
    key.algorithm.name.toUpperCase() === "HMAC" &&
    algorithm.length === undefined
  ) {
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

  if (
    ["HMAC", "RSASSA-PKCS1-v1_5", "RSA-PSS"].includes(registeredAlgorithmName)
  ) {
    assert_equals(
      key.algorithm.hash.name.toUpperCase(),
      algorithm.hash.toUpperCase(),
      "correct hash function"
    );
  }

  // usages is expected to be provided for a key pair, but we are checking
  // only a single key. The publicKey and privateKey portions of a key pair
  // recognize only some of the usages appropriate for a key pair.
  if (key.type === "public") {
    ["encrypt", "verify", "wrapKey"].forEach(function (usage) {
      if (usages.includes(usage)) {
        correctUsages.push(usage);
      }
    });
  } else if (key.type === "private") {
    ["decrypt", "sign", "unwrapKey", "deriveKey", "deriveBits"].forEach(
      function (usage) {
        if (usages.includes(usage)) {
          correctUsages.push(usage);
        }
      }
    );
  } else {
    correctUsages = usages;
  }

  assert_equals(
    typeof key.usages,
    "object",
    key.type + " key usages is an object"
  );
  assert_not_equals(key.usages, null, key.type + " key usages is not null");

  var usageCount = 0;
  key.usages.forEach(function (usage) {
    usageCount += 1;
    assert_in_array(usage, correctUsages, "has " + usage + " usage");
  });

  assert_equals(key.usages.length, usageCount, "usages property is correct");
}
