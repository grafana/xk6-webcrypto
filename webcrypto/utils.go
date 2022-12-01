package webcrypto

// Contains returns true if the slice Contains the value.
func Contains[T comparable](slice []T, value T) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// ContainsOnly returns true if the slice only contains values
// equal to the given value.
func ContainsOnly[T comparable](slice []T, values ...T) bool {
	for _, item := range slice {
		if !Contains(values, item) {
			return false
		}
	}

	return true
}
