package webcrypto

// Intersection returns the intersection of two slices, that is the elements
// that are present in both slices.
func Intersection[T comparable](lhs, rhs []T) []T {
	intersection := make([]T, 0, len(rhs))

	for _, v := range lhs {
		if Contains(rhs, v) && !Contains(intersection, v) {
			intersection = append(intersection, v)
		}
	}

	return intersection
}

// Contains returns true if the left-hand side slice contains the right-hand side value.
func Contains[T comparable](lhs []T, rhs T) bool {
	for _, value := range lhs {
		if value == rhs {
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
