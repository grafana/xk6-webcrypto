function assert_equals(actual, expected, description) {
  if (actual !== expected) {
    throw `assert_equals ${description} expected (${typeof expected}) ${expected} but got (${typeof actual}) ${actual}`;
  }
}

function assert_not_equals(actual, expected, description) {
  if (actual === expected) {
    throw `assert_not_equals ${description} got disallowed value ${actual}`;
  }
}

function assert_in_array(actual, expected, description) {
  if (expected.indexOf(actual) === -1) {
    throw `assert_in_array ${description} value ${actual} not in array ${expected}`;
  }
}

function assert_unreached(description) {
  throw `assert_unreached ${description}`;
}
