//
// helpers.js
//
// Helper functions used by several WebCryptoAPI tests
//

var registeredAlgorithmNames = [
  "RSASSA-PKCS1-v1_5",
  "RSA-PSS",
  "RSA-OAEP",
  "ECDSA",
  "ECDH",
  "AES-CTR",
  "AES-CBC",
  "AES-GCM",
  "AES-KW",
  "HMAC",
  "SHA-1",
  "SHA-256",
  "SHA-384",
  "SHA-512",
  "HKDF-CTR",
  "PBKDF2",
  "Ed25519",
  "Ed448",
  "X25519",
  "X448",
];

// Don't create an exhaustive list of all invalid usages,
// because there would usually be nearly 2**8 of them,
// way too many to test. Instead, create every singleton
// of an illegal usage, and "poison" every valid usage
// with an illegal one.
function invalidUsages(validUsages, mandatoryUsages) {
  var results = [];

  var illegalUsages = [];
  [
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "wrapKey",
    "unwrapKey",
    "deriveKey",
    "deriveBits",
  ].forEach(function (usage) {
    if (!validUsages.includes(usage)) {
      illegalUsages.push(usage);
    }
  });

  var goodUsageCombinations = allValidUsages(
    validUsages,
    false,
    mandatoryUsages
  );

  illegalUsages.forEach(function (illegalUsage) {
    results.push([illegalUsage]);
    goodUsageCombinations.forEach(function (usageCombination) {
      results.push(usageCombination.concat([illegalUsage]));
    });
  });

  return results;
}

// Algorithm name specifiers are case-insensitive. Generate several
// case variations of a given name.
function allNameVariants(name) {
  var upCaseName = name.toUpperCase();
  var lowCaseName = name.toLowerCase();
  var mixedCaseName = upCaseName.substring(0, 1) + lowCaseName.substring(1);

  return unique([upCaseName, lowCaseName, mixedCaseName, name]);
}

function allValidUsages(validUsages, allowEmpty, mandatoryUsages) {
  if (typeof mandatoryUsages === "undefined") {
    mandatoryUsages = [];
  }

  var okaySubsets = [];
  allNonemptySubsetsOf(validUsages).forEach((subset) => {
    if (mandatoryUsages.length === 0) {
      okaySubsets.push(subset);
    } else {
      for (var i = 0; i < mandatoryUsages.length; i++) {
        if (subset.includes(mandatoryUsages[i])) {
          okaySubsets.push(subset);
          return;
        }
      }
    }
  });

  if (allowEmpty) {
    okaySubsets.push([]);
  }

  okaySubsets.push(validUsages.concat(mandatoryUsages).concat(validUsages));
  return okaySubsets;
}

// Treats an array as a set, and generates an array of all non-empty
// subsets (which are themselves arrays).
//
// The order of members of the "subsets" is not guaranteed.
function allNonemptySubsetsOf(arr) {
  var results = [];
  var firstElement;
  var remainingElements;

  for (var i = 0; i < arr.length; i++) {
    firstElement = arr[i];
    remainingElements = arr.slice(i + 1);
    results.push([firstElement]);

    if (remainingElements.length > 0) {
      allNonemptySubsetsOf(remainingElements).forEach(function (combination) {
        combination.push(firstElement);
        results.push(combination);
      });
    }
  }

  return results;
}

function unique(names) {
  return [...new Set(names)];
}

/**
 * @class
 * Exception type that represents a failing assert.
 *
 * @param {string} message - Error message.
 */
function AssertionError(message) {
  if (typeof message == "string") {
    message = sanitize_unpaired_surrogates(message);
  }
  this.message = message;
  this.stack = get_stack();
}
/*
 * Utility functions
 */
function assert(
  expected_true,
  function_name,
  description,
  error,
  substitutions
) {
  if (expected_true !== true) {
    var msg = `${function_name}, ${description}, ${error}, ${substitutions}`;
    throw new AssertionError(msg);
  }
}

/**
 * Assert that ``actual`` is the same value as ``expected``.
 *
 * For objects this compares by cobject identity; for primitives
 * this distinguishes between 0 and -0, and has correct handling
 * of NaN.
 *
 * @param {Any} actual - Test value.
 * @param {Any} expected - Expected value.
 * @param {string} [description] - Description of the condition being tested.
 */
function assert_equals(actual, expected, description) {
  /*
   * Test if two primitives are equal or two objects
   * are the same object
   */
  if (typeof actual != typeof expected) {
    assert(
      false,
      "assert_equals",
      description,
      "expected (" +
        typeof expected +
        ") ${expected} but got (" +
        typeof actual +
        ") ${actual}",
      { expected: expected, actual: actual }
    );
    return;
  }
  assert(
    same_value(actual, expected),
    "assert_equals",
    description,
    "expected ${expected} but got ${actual}",
    { expected: expected, actual: actual }
  );
}

// Is key a CryptoKey object with correct algorithm, extractable, and usages?
// Is it a secret, private, or public kind of key?
function assert_goodCryptoKey(key, algorithm, extractable, usages, kind) {
  var correctUsages = [];

  var registeredAlgorithmName;
  registeredAlgorithmNames.forEach(function (name) {
    if (name.toUpperCase() === algorithm.name.toUpperCase()) {
      registeredAlgorithmName = name;
    }
  });

  assert_equals(key.constructor, CryptoKey, "Is a CryptoKey");
  assert_equals(key.type, kind, "Is a " + kind + " key");
  if (key.type === "public") {
    extractable = true; // public keys are always extractable
  }
  assert_equals(key.extractable, extractable, "Extractability is correct");

  assert_equals(
    key.algorithm.name,
    registeredAlgorithmName,
    "Correct algorithm name"
  );
  if (
    key.algorithm.name.toUpperCase() === "HMAC" &&
    algorithm.length === undefined
  ) {
    switch (key.algorithm.hash.name.toUpperCase()) {
      case "SHA-1":
      case "SHA-256":
        assert_equals(key.algorithm.length, 512, "Correct length");
        break;
      case "SHA-384":
      case "SHA-512":
        assert_equals(key.algorithm.length, 1024, "Correct length");
        break;
      default:
        assert_unreached("Unrecognized hash");
    }
  } else {
    assert_equals(key.algorithm.length, algorithm.length, "Correct length");
  }
  if (
    ["HMAC", "RSASSA-PKCS1-v1_5", "RSA-PSS"].includes(registeredAlgorithmName)
  ) {
    assert_equals(
      key.algorithm.hash.name.toUpperCase(),
      algorithm.hash.toUpperCase(),
      "Correct hash function"
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
    key.type + " key.usages is an object"
  );
  assert_not_equals(key.usages, null, key.type + " key.usages isn't null");

  // The usages parameter could have repeats, but the usages
  // property of the result should not.
  var usageCount = 0;
  key.usages.forEach(function (usage) {
    usageCount += 1;
    assert_in_array(usage, correctUsages, "Has " + usage + " usage");
  });
  assert_equals(key.usages.length, usageCount, "usages property is correct");
}

// The algorithm parameter is an object with a name and other
// properties. Given the name, generate all valid parameters.
function allAlgorithmSpecifiersFor(algorithmName) {
  var results = [];

  // RSA key generation is slow. Test a minimal set of parameters
  var hashes = ["SHA-1", "SHA-256"];

  // EC key generation is a lot faster. Check all curves in the spec
  var curves = ["P-256", "P-384", "P-521"];

  if (algorithmName.toUpperCase().substring(0, 3) === "AES") {
    // Specifier properties are name and length
    [128, 192, 256].forEach(function (length) {
      results.push({ name: algorithmName, length: length });
    });
  } else if (algorithmName.toUpperCase() === "HMAC") {
    [
      { hash: "SHA-1", length: 160 },
      { hash: "SHA-256", length: 256 },
      { hash: "SHA-384", length: 384 },
      { hash: "SHA-512", length: 512 },
      { hash: "SHA-1" },
      { hash: "SHA-256" },
      { hash: "SHA-384" },
      { hash: "SHA-512" },
    ].forEach(function (hashAlgorithm) {
      results.push({ name: algorithmName, ...hashAlgorithm });
    });
  } else if (algorithmName.toUpperCase().substring(0, 3) === "RSA") {
    hashes.forEach(function (hashName) {
      results.push({
        name: algorithmName,
        hash: hashName,
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      });
    });
  } else if (algorithmName.toUpperCase().substring(0, 2) === "EC") {
    curves.forEach(function (curveName) {
      results.push({ name: algorithmName, namedCurve: curveName });
    });
  } else if (
    algorithmName.toUpperCase().substring(0, 1) === "X" ||
    algorithmName.toUpperCase().substring(0, 2) === "ED"
  ) {
    results.push({ name: algorithmName });
  }

  return results;
}
