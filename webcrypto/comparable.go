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
