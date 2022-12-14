package webcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntersection(t *testing.T) {
	t.Parallel()

	type args struct {
		lhs []int
		rhs []int
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{
			name: "empty slices",
			args: args{
				lhs: []int{},
				rhs: []int{},
			},
			want: []int{},
		},
		{
			name: "empty lhs",
			args: args{
				lhs: []int{},
				rhs: []int{1, 2, 3},
			},
			want: []int{},
		},
		{
			name: "empty rhs",
			args: args{
				lhs: []int{1, 2, 3},
				rhs: []int{},
			},
			want: []int{},
		},
		{
			name: "no intersection",
			args: args{
				lhs: []int{1, 2, 3},
				rhs: []int{4, 5, 6},
			},
			want: []int{},
		},
		{
			name: "intersection",
			args: args{
				lhs: []int{1, 2, 3},
				rhs: []int{3, 4, 5},
			},
			want: []int{3},
		},
		{
			name: "multiple intersections",
			args: args{
				lhs: []int{1, 2, 3},
				rhs: []int{3, 4, 5, 3},
			},
			want: []int{3},
		},
		{
			name: "multiple intersections with duplicates",
			args: args{
				lhs: []int{1, 2, 3, 3},
				rhs: []int{3, 4, 5, 3},
			},
			want: []int{3},
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Intersection(tt.args.lhs, tt.args.rhs)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContains(t *testing.T) {
	t.Parallel()

	type args struct {
		lhs []int
		rhs int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "empty slice",
			args: args{
				lhs: []int{},
				rhs: 1,
			},
			want: false,
		},
		{
			name: "not found",
			args: args{
				lhs: []int{1, 2, 3},
				rhs: 4,
			},
			want: false,
		},
		{
			name: "found",
			args: args{
				lhs: []int{1, 2, 3},
				rhs: 2,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Contains(tt.args.lhs, tt.args.rhs)
			assert.Equal(t, tt.want, got)
		})
	}
}
