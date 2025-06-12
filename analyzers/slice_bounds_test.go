// (c) Copyright gosec's authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyzers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"golang.org/x/tools/go/ssa"
)

// allocsFromCode creates SSA from a Go code snippet and returns any *ssa.Alloc instructions found
func allocsFromCode(code string) ([]*ssa.Alloc, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", code, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}

	conf := &types.Config{}
	tpkg, err := conf.Check("test", fset, []*ast.File{file}, info)
	if err != nil {
		return nil, err
	}

	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)
	ssaPkg := prog.CreatePackage(tpkg, []*ast.File{file}, info, false)
	ssaPkg.Build()

	var allocs []*ssa.Alloc
	for _, member := range ssaPkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					if alloc, ok := instr.(*ssa.Alloc); ok {
						allocs = append(allocs, alloc)
					}
				}
			}
		}
	}

	return allocs, nil
}

// slicesFromCode creates SSA from a Go code snippet and returns any *ssa.Slice instructions found
func slicesFromCode(code string) ([]*ssa.Slice, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", code, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}

	conf := &types.Config{}
	tpkg, err := conf.Check("test", fset, []*ast.File{file}, info)
	if err != nil {
		return nil, err
	}

	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)
	ssaPkg := prog.CreatePackage(tpkg, []*ast.File{file}, info, false)
	ssaPkg.Build()

	var slices []*ssa.Slice
	for _, member := range ssaPkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					if slice, ok := instr.(*ssa.Slice); ok {
						slices = append(slices, slice)
					}
				}
			}
		}
	}

	return slices, nil
}

func TestExtractSliceCapFromString(t *testing.T) {
	tests := []struct {
		name        string
		allocString string
		expectedCap int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "zero capacity slice",
			allocString: "t0 = new [0]int",
			expectedCap: 0,
			expectError: false,
		},
		{
			name:        "single capacity slice",
			allocString: "t0 = new [1]int",
			expectedCap: 1,
			expectError: false,
		},
		{
			name:        "small capacity slice",
			allocString: "t0 = new [10]int",
			expectedCap: 10,
			expectError: false,
		},
		{
			name:        "large capacity slice",
			allocString: "t0 = new [1000]int",
			expectedCap: 1000,
			expectError: false,
		},
		{
			name:        "very large capacity slice",
			allocString: "t0 = new [999999]int",
			expectedCap: 999999,
			expectError: false,
		},
		{
			name:        "no slice allocation",
			allocString: "t0 = new int",
			expectedCap: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice cap match, found 0",
		},
		{
			name:        "invalid format",
			allocString: "invalid allocation string",
			expectedCap: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice cap match, found 0",
		},
		{
			name:        "multiple array allocations",
			allocString: "t0 = new [10]int, t1 = new [20]int",
			expectedCap: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice cap match, found 2",
		},
		{
			name:        "non-numeric capacity",
			allocString: "t0 = new [abc]int",
			expectedCap: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice cap match, found 0",
		},
		{
			name:        "empty brackets",
			allocString: "t0 = new []int",
			expectedCap: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice cap match, found 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cap, err := extractSliceCapFromString(tt.allocString)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if cap != tt.expectedCap {
					t.Errorf("expected capacity %d, got %d", tt.expectedCap, cap)
				}
			}
		})
	}
}

func TestExtractSliceLenFromString(t *testing.T) {
	tests := []struct {
		name        string
		sliceString string
		expectedLen int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "zero length slice",
			sliceString: "slice t0[:0:int]",
			expectedLen: 0,
			expectError: false,
		},
		{
			name:        "single length slice",
			sliceString: "slice t0[:1:int]",
			expectedLen: 1,
			expectError: false,
		},
		{
			name:        "small length slice",
			sliceString: "slice t0[:5:int]",
			expectedLen: 5,
			expectError: false,
		},
		{
			name:        "large length slice",
			sliceString: "slice t0[:100:int]",
			expectedLen: 100,
			expectError: false,
		},
		{
			name:        "slice with different variable name",
			sliceString: "slice t1[:25:int]",
			expectedLen: 25,
			expectError: false,
		},
		{
			name:        "no slice operation",
			sliceString: "t0 = new int",
			expectedLen: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice len match, found 0",
		},
		{
			name:        "invalid format",
			sliceString: "invalid slice string",
			expectedLen: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice len match, found 0",
		},
		{
			name:        "multiple slice operations",
			sliceString: "slice t0[:5:int], slice t1[:10:int]",
			expectedLen: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice len match, found 2",
		},
		{
			name:        "non-numeric length",
			sliceString: "slice t0[:abc:int]",
			expectedLen: 0,
			expectError: true,
			errorMsg:    "expected exactly 1 slice len match, found 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, err := extractSliceLenFromString(tt.sliceString)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if length != tt.expectedLen {
					t.Errorf("expected length %d, got %d", tt.expectedLen, length)
				}
			}
		})
	}
}

func TestExtractSliceLenFromSliceWithRealSSA(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectedLen int
		expectError bool
	}{
		{
			name: "zero length slice",
			code: `
package test
func test() []int {
	s := make([]int, 0, 5)
	return s
}`,
			expectedLen: 0,
			expectError: false,
		},
		{
			name: "small length slice",
			code: `
package test
func test() []int {
	s := make([]int, 3, 10)
	return s
}`,
			expectedLen: 3,
			expectError: false,
		},
		{
			name: "slice with same length and capacity",
			code: `
package test
func test() []int {
	s := make([]int, 7)
	return s
}`,
			expectedLen: 7,
			expectError: false,
		},
		{
			name: "named type slice",
			code: `
package test
type IntSlice []int
func test() IntSlice {
	s := make(IntSlice, 5, 10)
	return s
}`,
			expectedLen: 5,
			expectError: false,
		},
		{
			name: "multi-declaration line",
			code: `
package test
func test() ([]int, []string) {
	s1, s2 := make([]int, 3, 8), make([]string, 7, 12)
	return s1, s2
}`,
			expectedLen: 3,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slices, err := slicesFromCode(tt.code)
			if err != nil {
				t.Fatalf("failed to create SSA: %v", err)
			}

			if len(slices) == 0 {
				t.Fatal("no slice instructions found in SSA")
			}

			length, err := extractSliceLenFromSlice(slices[0])

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if length != tt.expectedLen {
					t.Errorf("expected length %d, got %d", tt.expectedLen, length)
				}
			}
		})
	}
}

func TestExtractSliceLenFromMultiDeclaration(t *testing.T) {
	code := `
package test
func test() ([]int, []string) {
	s1, s2 := make([]int, 3, 8), make([]string, 7, 12)
	return s1, s2
}`
	slices, err := slicesFromCode(code)
	if err != nil {
		t.Fatalf("failed to create SSA: %v", err)
	}

	if len(slices) < 2 {
		t.Fatalf("expected at least 2 slice instructions, found %d", len(slices))
	}

	// Test the first slice (make([]int, 3, 8))
	length1, err := extractSliceLenFromSlice(slices[0])
	if err != nil {
		t.Errorf("unexpected error for first slice: %v", err)
	} else if length1 != 3 {
		t.Errorf("expected length 3 for first slice, got %d", length1)
	}

	// Test the second slice (make([]string, 7, 12))
	length2, err := extractSliceLenFromSlice(slices[1])
	if err != nil {
		t.Errorf("unexpected error for second slice: %v", err)
	} else if length2 != 7 {
		t.Errorf("expected length 7 for second slice, got %d", length2)
	}
}

func TestExtractSliceCapFromAllocWithRealSSA(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectedCap int
		expectError bool
	}{
		{
			name: "zero capacity array",
			code: `
package test
func test() *[0]int {
	return new([0]int)
}`,
			expectedCap: 0,
			expectError: false,
		},
		{
			name: "small capacity array",
			code: `
package test
func test() *[5]int {
	return new([5]int)
}`,
			expectedCap: 5,
			expectError: false,
		},
		{
			name: "large capacity array",
			code: `
package test
func test() *[100]int {
	return new([100]int)
}`,
			expectedCap: 100,
			expectError: false,
		},
		{
			name: "named type backed by array",
			code: `
package test
type MyArray [25]int
func test() *MyArray {
	return new(MyArray)
}`,
			expectedCap: 0,
			expectError: true,
		},
		{
			name: "named type backed by slice",
			code: `
package test
type MySlice []int
func test() MySlice {
	return make(MySlice, 0)
}`,
			expectedCap: 0,
			expectError: false,
		},
		{
			name: "nested named type backed by slice",
			code: `
package test
type BaseSlice []string
type MySlice BaseSlice
func test() MySlice {
	return make(MySlice, 0)
}`,
			expectedCap: 0,
			expectError: false,
		},
		{
			name: "named type with slice allocation",
			code: `
package test
type IntSlice []int
func test() IntSlice {
	s := make(IntSlice, 5, 10)
	return s
}`,
			expectedCap: 10,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocs, err := allocsFromCode(tt.code)
			if err != nil {
				t.Fatalf("failed to create SSA: %v", err)
			}

			if len(allocs) == 0 {
				t.Fatal("no allocations found in SSA")
			}

			cap, err := extractSliceCapFromAlloc(allocs[0])

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if cap != tt.expectedCap {
					t.Errorf("expected capacity %d, got %d", tt.expectedCap, cap)
				}
			}
		})
	}
}

func TestExtractSliceLenAndCapFromSlice(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectedLen int
		expectedCap int
		expectError bool
		errorMsg    string
	}{
		{
			name: "make slice with length and capacity",
			code: `
package test
func test() []int {
	s := make([]int, 5, 10)
	return s
}`,
			expectedLen: 5,
			expectedCap: 10,
			expectError: false,
		},
		{
			name: "make slice with same length and capacity",
			code: `
package test
func test() []int {
	s := make([]int, 7)
	return s
}`,
			expectedLen: 7,
			expectedCap: 7,
			expectError: false,
		},
		{
			name: "zero length slice with capacity",
			code: `
package test
func test() []int {
	s := make([]int, 0, 15)
	return s
}`,
			expectedLen: 0,
			expectedCap: 15,
			expectError: false,
		},
		{
			name: "named type slice",
			code: `
package test
type IntSlice []int
func test() IntSlice {
	s := make(IntSlice, 3, 8)
	return s
}`,
			expectedLen: 3,
			expectedCap: 8,
			expectError: false,
		},
		{
			name: "nested named type slice",
			code: `
package test
type BaseSlice []string
type MySlice BaseSlice
func test() MySlice {
	s := make(MySlice, 2, 6)
	return s
}`,
			expectedLen: 2,
			expectedCap: 6,
			expectError: false,
		},
		{
			name: "large capacity slice",
			code: `
package test
func test() []int {
	s := make([]int, 50, 100)
	return s
}`,
			expectedLen: 50,
			expectedCap: 100,
			expectError: false,
		},
		{
			name: "multi-declaration first slice",
			code: `
package test
func test() ([]int, []string) {
	s1, s2 := make([]int, 4, 12), make([]string, 6, 18)
	return s1, s2
}`,
			expectedLen: 4,
			expectedCap: 12,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slices, err := slicesFromCode(tt.code)
			if err != nil {
				t.Fatalf("failed to create SSA: %v", err)
			}

			if len(slices) == 0 {
				t.Fatal("no slice instructions found in SSA")
			}

			length, capacity, err := extractSliceLenAndCapFromSlice(slices[0])

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if length != tt.expectedLen {
					t.Errorf("expected length %d, got %d", tt.expectedLen, length)
				}
				if capacity != tt.expectedCap {
					t.Errorf("expected capacity %d, got %d", tt.expectedCap, capacity)
				}
			}
		})
	}
}

func TestExtractSliceLenAndCapFromSliceAdvanced(t *testing.T) {
	// Test multi-declaration both slices
	t.Run("multi-declaration both slices", func(t *testing.T) {
		code := `
package test
func test() ([]int, []string) {
	s1, s2 := make([]int, 4, 12), make([]string, 6, 18)
	return s1, s2
}`
		slices, err := slicesFromCode(code)
		if err != nil {
			t.Fatalf("failed to create SSA: %v", err)
		}

		if len(slices) < 2 {
			t.Fatalf("expected at least 2 slice instructions, found %d", len(slices))
		}

		// Test first slice
		length1, capacity1, err := extractSliceLenAndCapFromSlice(slices[0])
		if err != nil {
			t.Errorf("unexpected error for first slice: %v", err)
		} else {
			if length1 != 4 {
				t.Errorf("expected length 4 for first slice, got %d", length1)
			}
			if capacity1 != 12 {
				t.Errorf("expected capacity 12 for first slice, got %d", capacity1)
			}
		}

		// Test second slice
		length2, capacity2, err := extractSliceLenAndCapFromSlice(slices[1])
		if err != nil {
			t.Errorf("unexpected error for second slice: %v", err)
		} else {
			if length2 != 6 {
				t.Errorf("expected length 6 for second slice, got %d", length2)
			}
			if capacity2 != 18 {
				t.Errorf("expected capacity 18 for second slice, got %d", capacity2)
			}
		}
	})

	// Test 3-index slice
	t.Run("3-index slice", func(t *testing.T) {
		code := `
package test
func test() []int {
	arr := [10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	s := arr[2:7:9]
	return s
}`
		slices, err := slicesFromCode(code)
		if err != nil {
			t.Fatalf("failed to create SSA: %v", err)
		}

		if len(slices) == 0 {
			t.Fatal("no slice instructions found in SSA")
		}

		length, capacity, err := extractSliceLenAndCapFromSlice(slices[0])
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		} else {
			expectedLength := 5   // 7 - 2
			expectedCapacity := 7 // 9 - 2
			if length != expectedLength {
				t.Errorf("expected length %d, got %d", expectedLength, length)
			}
			if capacity != expectedCapacity {
				t.Errorf("expected capacity %d, got %d", expectedCapacity, capacity)
			}
		}
	})

	// Test error cases (slices that don't come from make or 3-index)
	t.Run("parameter slice - capacity unknown", func(t *testing.T) {
		code := `
package test
func test(input []int) []int {
	s := input[1:5]
	return s
}`
		slices, err := slicesFromCode(code)
		if err != nil {
			t.Fatalf("failed to create SSA: %v", err)
		}

		if len(slices) == 0 {
			t.Fatal("no slice instructions found in SSA")
		}

		length, capacity, err := extractSliceLenAndCapFromSlice(slices[0])
		if err == nil {
			t.Errorf("expected error for parameter slice, but got length=%d, capacity=%d", length, capacity)
		} else {
			expectedError := "could not determine slice capacity"
			if err.Error() != expectedError {
				t.Errorf("expected error '%s', got '%s'", expectedError, err.Error())
			}
		}
	})
}

// allocsAndSlicesFromCode creates SSA from a Go code snippet and returns both *ssa.Alloc and *ssa.Slice instructions
func allocsAndSlicesFromCode(code string) ([]*ssa.Alloc, []*ssa.Slice, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", code, parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}

	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}

	conf := &types.Config{}
	tpkg, err := conf.Check("test", fset, []*ast.File{file}, info)
	if err != nil {
		return nil, nil, err
	}

	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)
	ssaPkg := prog.CreatePackage(tpkg, []*ast.File{file}, info, false)
	ssaPkg.Build()

	var allocs []*ssa.Alloc
	var slices []*ssa.Slice
	for _, member := range ssaPkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					if alloc, ok := instr.(*ssa.Alloc); ok {
						allocs = append(allocs, alloc)
					}
					if slice, ok := instr.(*ssa.Slice); ok {
						slices = append(slices, slice)
					}
				}
			}
		}
	}

	return allocs, slices, nil
}

func TestProcessMakeSliceAlloc(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectedLen uint
		expectedCap uint
		expectError bool
		errorMsg    string
	}{
		{
			name: "make slice with length only - alloc processing",
			code: `
package main
func main() {
	s := make([]int, 5)
	_ = s
}`,
			expectedLen: 5,
			expectedCap: 5,
			expectError: false,
		},
		{
			name: "make slice with length and capacity - alloc processing",
			code: `
package main
func main() {
	s := make([]int, 3, 10)
	_ = s
}`,
			expectedLen: 3,
			expectedCap: 10,
			expectError: false,
		},
		{
			name: "make slice with zero length and capacity - alloc processing",
			code: `
package main
func main() {
	s := make([]int, 0, 5)
	_ = s
}`,
			expectedLen: 0,
			expectedCap: 5,
			expectError: false,
		},
		{
			name: "make slice with zero length - alloc processing",
			code: `
package main
func main() {
	s := make([]byte, 0)
	_ = s
}`,
			expectedLen: 0,
			expectedCap: 0,
			expectError: false,
		},
		{
			name: "make slice with large values - alloc processing",
			code: `
package main
func main() {
	s := make([]string, 50, 200)
	_ = s
}`,
			expectedLen: 50,
			expectedCap: 200,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocs, _, err := allocsAndSlicesFromCode(tt.code)
			if err != nil {
				t.Fatalf("failed to create SSA: %v", err)
			}

			// Find the makeslice alloc (should contain "makeslice" in the string representation)
			var makeSliceAlloc *ssa.Alloc
			for _, alloc := range allocs {
				if strings.Contains(alloc.String(), "makeslice") {
					makeSliceAlloc = alloc
					break
				}
			}

			if makeSliceAlloc == nil {
				t.Fatalf("no makeslice alloc found in SSA")
			}

			bounds, err := processMakeSliceAlloc(makeSliceAlloc)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if bounds.safeLen != tt.expectedLen {
					t.Errorf("expected length %d, got %d", tt.expectedLen, bounds.safeLen)
				}
				if bounds.safeCap != tt.expectedCap {
					t.Errorf("expected capacity %d, got %d", tt.expectedCap, bounds.safeCap)
				}
				if !bounds.isLenExact {
					t.Errorf("expected isLenExact to be true")
				}
				if !bounds.isCapExact {
					t.Errorf("expected isCapExact to be true")
				}
			}
		})
	}
}

func TestProcessMakeSliceAllocEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectError bool
		errorMsg    string
	}{
		{
			name: "non-slice alloc should error",
			code: `
package main
func main() {
	x := new(int)
	_ = x
}`,
			expectError: true,
		},
		{
			name: "array alloc should error",
			code: `
package main
func main() {
	arr := [5]int{}
	println(arr)
}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocs, _, err := allocsAndSlicesFromCode(tt.code)
			if err != nil {
				t.Fatalf("failed to create SSA: %v", err)
			}

			if len(allocs) == 0 {
				t.Skip("no allocs found - this is expected for some test cases")
			}

			// Try to process the first alloc
			_, err = processMakeSliceAlloc(allocs[0])

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestMakeSliceProcessingIntegration(t *testing.T) {
	// This test verifies that the critical case that was failing is now working
	code := `
package main
func main() {
	s := make([]byte, 0, 4)
	_ = s[:3]
	_ = s[3]
}`

	allocs, _, err := allocsAndSlicesFromCode(code)
	if err != nil {
		t.Fatalf("failed to create SSA: %v", err)
	}

	// Find the makeslice alloc
	var makeSliceAlloc *ssa.Alloc
	for _, alloc := range allocs {
		if strings.Contains(alloc.String(), "makeslice") {
			makeSliceAlloc = alloc
			break
		}
	}

	if makeSliceAlloc == nil {
		t.Fatalf("no makeslice alloc found in SSA")
	}

	bounds, err := processMakeSliceAlloc(makeSliceAlloc)
	if err != nil {
		t.Fatalf("failed to process make slice alloc: %v", err)
	}

	// Verify the critical fix: length should be 0, capacity should be 4
	if bounds.safeLen != 0 {
		t.Errorf("expected length 0, got %d", bounds.safeLen)
	}
	if bounds.safeCap != 4 {
		t.Errorf("expected capacity 4, got %d", bounds.safeCap)
	}
	if !bounds.isLenExact || !bounds.isCapExact {
		t.Errorf("expected both length and capacity to be exact")
	}
}
