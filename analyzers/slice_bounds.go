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
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/securego/gosec/v2/issue"
)

type bound int

const (
	lowerUnbounded bound = iota
	upperUnbounded
	unbounded
	upperBounded
)

var sliceCapRegex = regexp.MustCompile(`new \[(\d+)\]\w*(?:\s*\((?:new|makeslice)\))?`)
var sliceLenRegex = regexp.MustCompile(`slice \w+\[:(\d+):`)

func newSliceBoundsAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runSliceBounds,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runSliceBounds(pass *analysis.Pass) (interface{}, error) {
	return runSliceBoundsWithClosures(pass)
}

func invBound(bound bound) bound {
	switch bound {
	case lowerUnbounded:
		return upperUnbounded
	case upperUnbounded:
		return lowerUnbounded
	case upperBounded:
		return unbounded
	case unbounded:
		return upperBounded
	default:
		return unbounded
	}
}

func extractSliceBounds(slice *ssa.Slice) (int, int) {
	var low int
	if slice.Low != nil {
		l, err := extractNumberColonInt(slice.Low.String())
		if err == nil {
			low = l
		}
	}
	var high int
	if slice.High != nil {
		h, err := extractNumberColonInt(slice.High.String())
		if err == nil {
			high = h
		}
	}
	return low, high
}

func extractNumberColonInt(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid string: %s", s)
	}
	if parts[1] != "int" {
		return 0, fmt.Errorf("invalid string: %s", s)
	}
	return strconv.Atoi(parts[0])
}

func extractSliceCapFromString(allocString string) (int, error) {
	matches := sliceCapRegex.FindAllStringSubmatch(allocString, -1)
	if len(matches) != 1 {
		return 0, fmt.Errorf("expected exactly 1 slice cap match, found %d", len(matches))
	}
	m := matches[0]
	if len(m) <= 1 {
		return 0, errors.New("regex matched but failed to capture slice capacity")
	}
	return strconv.Atoi(m[1])
}

func extractSliceCapFromAlloc(a *ssa.Alloc) (int, error) {
	return extractSliceCapFromString(a.String())
}

func extractSliceLenFromString(sliceString string) (int, error) {
	matches := sliceLenRegex.FindAllStringSubmatch(sliceString, -1)
	if len(matches) != 1 {
		return 0, fmt.Errorf("expected exactly 1 slice len match, found %d", len(matches))
	}
	m := matches[0]
	if len(m) <= 1 {
		return 0, errors.New("regex matched but failed to capture slice length")
	}
	return strconv.Atoi(m[1])
}

func extractSliceLenFromSlice(s *ssa.Slice) (int, error) {
	return extractSliceLenFromString(s.String())
}

// extractSliceLenAndCapFromSlice extracts both length and capacity from a *ssa.Slice instruction
// Returns (length, capacity, error). For make() slices, capacity comes from underlying *ssa.Alloc.
// For 3-index slices (arr[low:high:max]), both length and capacity are computed from bounds.
func extractSliceLenAndCapFromSlice(s *ssa.Slice) (int, int, error) {
	// Check if this is a 3-index slice (has Max field)
	if s.Max != nil {
		// For 3-index slices: arr[low:high:max]
		// Length = high - low, Capacity = max - low
		low := 0
		if s.Low != nil {
			if lowConst, ok := s.Low.(*ssa.Const); ok {
				if lowVal, err := strconv.Atoi(lowConst.Value.String()); err == nil {
					low = lowVal
				}
			}
		}

		high := 0
		if s.High != nil {
			if highConst, ok := s.High.(*ssa.Const); ok {
				if highVal, err := strconv.Atoi(highConst.Value.String()); err == nil {
					high = highVal
				}
			}
		}

		if maxConst, ok := s.Max.(*ssa.Const); ok {
			if maxVal, err := strconv.Atoi(maxConst.Value.String()); err == nil {
				length := high - low
				capacity := maxVal - low
				return length, capacity, nil
			}
		}
		return 0, 0, errors.New("could not extract bounds from 3-index slice")
	}

	// For regular slices (including make() and 2-index), try to extract length from string representation
	length, err := extractSliceLenFromSlice(s)
	if err != nil {
		// If string parsing fails, try to compute from High and Low fields
		if s.High != nil && s.Low != nil {
			low := 0
			if lowConst, ok := s.Low.(*ssa.Const); ok {
				if lowVal, err := strconv.Atoi(lowConst.Value.String()); err == nil {
					low = lowVal
				}
			}

			if highConst, ok := s.High.(*ssa.Const); ok {
				if highVal, err := strconv.Atoi(highConst.Value.String()); err == nil {
					length = highVal - low
				} else {
					return 0, 0, fmt.Errorf("failed to extract length: %w", err)
				}
			} else {
				return 0, 0, fmt.Errorf("failed to extract length: %w", err)
			}
		} else {
			return 0, 0, fmt.Errorf("failed to extract length: %w", err)
		}
	}

	// For make() slices, capacity comes from the underlying allocation
	if alloc, ok := s.X.(*ssa.Alloc); ok {
		capacity, err := extractSliceCapFromAlloc(alloc)
		if err != nil {
			return length, 0, fmt.Errorf("failed to extract capacity from alloc: %w", err)
		}
		return length, capacity, nil
	}

	// If we can't determine capacity, return just the length
	return length, 0, errors.New("could not determine slice capacity")
}

// getSliceSource traces back to find the original slice source (Alloc, Parameter, etc.)
func getSliceSource(v ssa.Value) ssa.Value {
	for {
		switch val := v.(type) {
		case *ssa.ChangeType:
			v = val.X
		case *ssa.Slice:
			v = val.X
		default:
			return v
		}
	}
}

func isSliceType(t types.Type) bool {
	if named, ok := t.(*types.Named); ok {
		t = named.Underlying()
	}
	_, ok := t.(*types.Slice)
	return ok
}

// SliceScopeState represents the bounds checking state within a scope
type SliceScopeState struct {
	safeBounds  map[ssa.Value]BoundInfo // Maps slice sources to their known safe bounds
	parentScope *SliceScopeState        // Parent scope for lexical scoping
	errors      []*issue.Issue          // Accumulated errors in this scope
}

// BoundInfo represents what we know about a slice's bounds
type BoundInfo struct {
	minSafeIndex int  // Minimum guaranteed safe index
	maxSafeIndex int  // Maximum guaranteed safe index (-1 if unknown)
	isExact      bool // Whether bounds are exact (local slice) or conservative (parameter)
}

// ScopeContext manages the parsing context with closures
type ScopeContext struct {
	pass     *analysis.Pass
	analyzer *analysis.Analyzer
}

// WithScope creates a new scope and executes the given function within it
func (ctx *ScopeContext) WithScope(parent *SliceScopeState, fn func(*SliceScopeState)) *SliceScopeState {
	scope := &SliceScopeState{
		safeBounds:  make(map[ssa.Value]BoundInfo),
		parentScope: parent,
		errors:      []*issue.Issue{},
	}

	// Copy parent bounds to current scope (inheritance)
	if parent != nil {
		for k, v := range parent.safeBounds {
			scope.safeBounds[k] = v
		}
	}

	fn(scope)
	return scope
}

// WithCondition creates a new scope with updated bounds based on a condition
func (ctx *ScopeContext) WithCondition(parent *SliceScopeState, condition *ssa.BinOp, conditionTrue bool, fn func(*SliceScopeState)) *SliceScopeState {
	return ctx.WithScope(parent, func(scope *SliceScopeState) {
		// Update bounds based on the condition
		ctx.applyConditionToBounds(scope, condition, conditionTrue)
		fn(scope)
	})
}

// checkSliceAccess performs immediate bounds checking and accumulates errors
func (ctx *ScopeContext) checkSliceAccess(scope *SliceScopeState, access ssa.Instruction) {
	switch instr := access.(type) {
	case *ssa.IndexAddr:
		ctx.checkIndexAccess(scope, instr)
	case *ssa.Slice:
		ctx.checkSliceOperation(scope, instr)
	}
}

// checkIndexAccess validates a slice index access
func (ctx *ScopeContext) checkIndexAccess(scope *SliceScopeState, ia *ssa.IndexAddr) {
	indexValue, err := extractNumberColonInt(ia.Index.String())
	if err != nil {
		return // Cannot statically analyze dynamic indices
	}

	sliceSource := getSliceSource(ia.X)
	bounds, hasBounds := scope.safeBounds[sliceSource]

	// Check bounds for index access

	if !hasBounds {
		// Unknown slice - report error to encourage defensive programming
		ctx.addSliceError(scope, ia, "slice index out of range")
		return
	}

	if bounds.isExact && bounds.minSafeIndex >= 0 && bounds.maxSafeIndex >= bounds.minSafeIndex {
		// Known exact bounds (local slice) - check them precisely
		if indexValue >= bounds.maxSafeIndex || indexValue < bounds.minSafeIndex {
			fmt.Printf("ERROR: index=%d, bounds=[%d,%d), exact=%t at %s\n", indexValue, bounds.minSafeIndex, bounds.maxSafeIndex, bounds.isExact, ctx.pass.Fset.Position(ia.Pos()))
			ctx.addSliceError(scope, ia, "slice index out of range")
		} else {
			fmt.Printf("SAFE: index=%d, bounds=[%d,%d), exact=%t at %s\n", indexValue, bounds.minSafeIndex, bounds.maxSafeIndex, bounds.isExact, ctx.pass.Fset.Position(ia.Pos()))
		}
		// If within bounds, no error is reported
	} else if !bounds.isExact {
		// Parameter slice - check if we have safe bounds from conditions
		if bounds.maxSafeIndex >= 0 && indexValue < bounds.maxSafeIndex {
			// Access is within the guaranteed safe bounds for this parameter
			fmt.Printf("SAFE: index=%d, bounds=[%d,%d), exact=%t at %s\n", indexValue, bounds.minSafeIndex, bounds.maxSafeIndex, bounds.isExact, ctx.pass.Fset.Position(ia.Pos()))
			return
		}
		// Otherwise, report error to encourage defensive programming
		fmt.Printf("ERROR: index=%d, bounds=[%d,%d), exact=%t at %s\n", indexValue, bounds.minSafeIndex, bounds.maxSafeIndex, bounds.isExact, ctx.pass.Fset.Position(ia.Pos()))
		ctx.addSliceError(scope, ia, "slice index out of range")
	} else {
		// Other cases - need bounds from conditions to be safe
		if bounds.maxSafeIndex >= 0 && indexValue < bounds.maxSafeIndex {
			// Access is within the guaranteed safe bounds
			fmt.Printf("SAFE: index=%d, bounds=[%d,%d), exact=%t at %s\n", indexValue, bounds.minSafeIndex, bounds.maxSafeIndex, bounds.isExact, ctx.pass.Fset.Position(ia.Pos()))
			return
		}
		// Report error if bounds are not sufficient
		fmt.Printf("ERROR: index=%d, bounds=[%d,%d), exact=%t at %s\n", indexValue, bounds.minSafeIndex, bounds.maxSafeIndex, bounds.isExact, ctx.pass.Fset.Position(ia.Pos()))
		ctx.addSliceError(scope, ia, "slice index out of range")
	}
}

// checkSliceOperation validates a slice operation
func (ctx *ScopeContext) checkSliceOperation(scope *SliceScopeState, slice *ssa.Slice) {
	low, high := extractSliceBounds(slice)
	sliceSource := getSliceSource(slice.X)
	bounds, hasBounds := scope.safeBounds[sliceSource]

	// Check bounds for slice operation

	if !hasBounds {
		// Unknown slice - report error and create new bounds for the result
		ctx.addSliceError(scope, slice, "slice bounds out of range")
		return
	}

	// Check if slice bounds are within known safe bounds
	if bounds.isExact && bounds.minSafeIndex >= 0 && bounds.maxSafeIndex >= bounds.minSafeIndex {
		// Known safe bounds (local slice) - check them precisely
		if low < bounds.minSafeIndex {
			ctx.addSliceError(scope, slice, "slice bounds out of range")
			return
		}

		if slice.High != nil {
			// Case: s[low:high] - explicit high bound
			if high > bounds.maxSafeIndex {
				ctx.addSliceError(scope, slice, "slice bounds out of range")
				return
			}
		} else {
			// Case: s[low:] - implicit high bound (goes to end of slice)
			if low > bounds.maxSafeIndex {
				ctx.addSliceError(scope, slice, "slice bounds out of range")
				return
			}
		}
	} else {
		// Parameter slice or unknown bounds - encourage defensive programming
		// Functions should check len() before accessing parameter slices
		ctx.addSliceError(scope, slice, "slice bounds out of range")
		return
	}

	// Create bounds info for the resulting slice
	var newMaxIndex int
	if slice.High != nil {
		// Explicit high bound: new capacity is high - low
		newMaxIndex = high - low
	} else {
		// Implicit high bound: new capacity is original capacity - low
		if bounds.maxSafeIndex >= 0 {
			newMaxIndex = bounds.maxSafeIndex - low
		} else {
			newMaxIndex = -1 // Unknown capacity
		}
	}

	newBounds := BoundInfo{
		minSafeIndex: 0,
		maxSafeIndex: newMaxIndex,
		isExact:      bounds.isExact,
	}
	scope.safeBounds[slice] = newBounds
}

// applyConditionToBounds updates the bounds based on a conditional
func (ctx *ScopeContext) applyConditionToBounds(scope *SliceScopeState, condition *ssa.BinOp, conditionTrue bool) {
	sliceParam, bound, value, err := ctx.extractLengthCondition(condition)
	if err != nil {
		return
	}

	existing, hasBounds := scope.safeBounds[sliceParam]
	if !hasBounds {
		existing = BoundInfo{minSafeIndex: -1, maxSafeIndex: -2, isExact: false}
	}

	// Apply the condition to refine bounds (defensive programming approach)
	newBounds := ctx.refineBounds(existing, bound, value, conditionTrue)
	fmt.Printf("CONDITION: slice=%s, conditionTrue=%t, oldBounds=[%d,%d), newBounds=[%d,%d)\n",
		sliceParam.String(), conditionTrue, existing.minSafeIndex, existing.maxSafeIndex, newBounds.minSafeIndex, newBounds.maxSafeIndex)
	scope.safeBounds[sliceParam] = newBounds
}

// refineBounds applies a condition to existing bounds
func (ctx *ScopeContext) refineBounds(existing BoundInfo, bound bound, value int, conditionTrue bool) BoundInfo {
	newBounds := existing

	if !conditionTrue {
		// Invert the bound when condition is false
		bound = invBound(bound)
		if bound == lowerUnbounded {
			value = value - 1 // len(s) < N becomes len(s) >= N-1
		}
	}

	// Calculate new bounds based on the condition
	var conditionBounds BoundInfo
	switch bound {
	case lowerUnbounded: // len(s) > value
		// len(s) > value means indices 0 through value are definitely safe
		conditionBounds = BoundInfo{
			minSafeIndex: 0,
			maxSafeIndex: value + 1, // +1 because maxSafeIndex is exclusive upper bound
			isExact:      false,
		}
	case upperUnbounded: // len(s) < value
		// len(s) < value means slice length is at most value-1, so no indices are guaranteed safe
		// For parameter slices, we can't assume any access is safe unless proven otherwise
		conditionBounds = BoundInfo{
			minSafeIndex: 0,
			maxSafeIndex: 0, // No indices are guaranteed safe for parameter slices
			isExact:      false,
		}
	case upperBounded: // len(s) == value
		// len(s) == value means indices 0 through value-1 are exactly safe
		conditionBounds = BoundInfo{
			minSafeIndex: 0,
			maxSafeIndex: value, // value is already the exclusive upper bound
			isExact:      true,
		}
	default:
		return existing // No change for other bound types
	}

	// Apply the condition bounds, considering the existing context
	// For sequential conditions in control flow, newer conditions provide
	// stronger guarantees and should generally replace weaker ones

	if existing.minSafeIndex < 0 || existing.maxSafeIndex < 0 {
		// If existing bounds are uninitialized, use condition bounds
		return conditionBounds
	}

	// For the common case where existing bounds are empty [0,0) and we get
	// a condition that makes some indices safe, we should use the condition bounds
	if existing.maxSafeIndex == 0 && conditionBounds.maxSafeIndex > 0 {
		return conditionBounds
	}

	// For lower bounds (len(s) > N), take the stronger guarantee (larger N)
	// For upper bounds (len(s) < N), take the intersection (more restrictive)
	switch bound {
	case lowerUnbounded:
		// len(s) > value means we have a minimum guarantee
		// Take the stronger guarantee (larger minimum)
		if conditionBounds.maxSafeIndex > existing.maxSafeIndex {
			return conditionBounds
		} else {
			return existing
		}
	default:
		// For other bounds types, take intersection (more restrictive)
		newBounds.minSafeIndex = max(existing.minSafeIndex, conditionBounds.minSafeIndex)
		newBounds.maxSafeIndex = min(existing.maxSafeIndex, conditionBounds.maxSafeIndex)
	}

	// Debug output to trace bounds refinement
	fmt.Printf("REFINE: existing=[%d,%d), condition=[%d,%d), result=[%d,%d)\n",
		existing.minSafeIndex, existing.maxSafeIndex,
		conditionBounds.minSafeIndex, conditionBounds.maxSafeIndex,
		newBounds.minSafeIndex, newBounds.maxSafeIndex)

	// If both are exact and match, result is exact
	newBounds.isExact = existing.isExact && conditionBounds.isExact &&
		existing.maxSafeIndex == conditionBounds.maxSafeIndex

	return newBounds
}

// addSliceError adds an error to the current scope
func (ctx *ScopeContext) addSliceError(scope *SliceScopeState, instr ssa.Instruction, message string) {
	issue := newIssue(
		ctx.analyzer.Name,
		message,
		ctx.pass.Fset,
		instr.Pos(),
		issue.Low,
		issue.High,
	)
	// Add instruction pointer info for deduplication
	issue.Autofix = fmt.Sprintf("instr:%p", instr)
	scope.errors = append(scope.errors, issue)
}

// isConditionStatic checks if a condition can be statically determined for exact bounds
func (ctx *ScopeContext) isConditionStatic(scope *SliceScopeState, condition *ssa.BinOp) (isAlwaysTrue, isAlwaysFalse bool) {
	sliceParam, bound, value, err := ctx.extractLengthCondition(condition)
	if err != nil {
		return false, false
	}

	existing, hasBounds := scope.safeBounds[sliceParam]
	if !hasBounds || !existing.isExact {
		return false, false // Can't determine for non-exact bounds
	}

	// For exact bounds, we can statically check conditions
	exactLength := existing.maxSafeIndex // maxSafeIndex is the exact length for exact bounds

	switch bound {
	case lowerUnbounded: // len(s) > value
		if exactLength > value {
			return true, false // Always true
		} else {
			return false, true // Always false
		}
	case upperUnbounded: // len(s) < value
		if exactLength < value {
			return true, false // Always true
		} else {
			return false, true // Always false
		}
	case upperBounded: // len(s) == value
		if exactLength == value {
			return true, false // Always true
		} else {
			return false, true // Always false
		}
	}

	return false, false // Can't determine
}

// extractLengthCondition extracts slice parameter and bounds from a condition
func (ctx *ScopeContext) extractLengthCondition(condition *ssa.BinOp) (ssa.Value, bound, int, error) {
	var sliceParam ssa.Value
	var boundType bound
	var value int

	// Check if X is a len() call and Y is a constant
	if call, ok := condition.X.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
			if len(call.Call.Args) > 0 {
				sliceParam = getSliceSource(call.Call.Args[0])
				if y, ok := condition.Y.(*ssa.Const); ok {
					if val, err := strconv.Atoi(y.Value.String()); err == nil {
						value = val
						switch condition.Op {
						case token.LSS:
							boundType = upperUnbounded // len(s) < N
						case token.LEQ:
							boundType = upperUnbounded // len(s) <= N
							value = value + 1          // Adjust for <= vs <
						case token.GTR:
							boundType = lowerUnbounded // len(s) > N
						case token.GEQ:
							boundType = lowerUnbounded // len(s) >= N
							value = value - 1          // Adjust for >= vs >
						case token.EQL:
							boundType = upperBounded // len(s) == N
						case token.NEQ:
							boundType = unbounded // len(s) != N
						}
						return sliceParam, boundType, value, nil
					}
				}
			}
		}
	}

	// Check if Y is a len() call and X is a constant
	if call, ok := condition.Y.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
			if len(call.Call.Args) > 0 {
				sliceParam = getSliceSource(call.Call.Args[0])
				if x, ok := condition.X.(*ssa.Const); ok {
					if val, err := strconv.Atoi(x.Value.String()); err == nil {
						value = val
						switch condition.Op {
						case token.LSS:
							boundType = lowerUnbounded // N < len(s)
						case token.LEQ:
							boundType = lowerUnbounded // N <= len(s)
							value = value - 1          // Adjust for <= vs <
						case token.GTR:
							boundType = upperUnbounded // N > len(s)
						case token.GEQ:
							boundType = upperUnbounded // N >= len(s)
							value = value + 1          // Adjust for >= vs >
						case token.EQL:
							boundType = upperBounded // N == len(s)
						case token.NEQ:
							boundType = unbounded // N != len(s)
						}
						return sliceParam, boundType, value, nil
					}
				}
			}
		}
	}

	return nil, lowerUnbounded, 0, fmt.Errorf("no length condition found")
}

// processBlockWithScope processes a basic block within a scope context
func (ctx *ScopeContext) processBlockWithScope(scope *SliceScopeState, block *ssa.BasicBlock) {
	ctx.processBlockWithScopeRecursive(scope, block, make(map[*ssa.BasicBlock]bool))
}

// processBlockWithScopeRecursive processes a basic block with visited tracking to prevent infinite loops
func (ctx *ScopeContext) processBlockWithScopeRecursive(scope *SliceScopeState, block *ssa.BasicBlock, visited map[*ssa.BasicBlock]bool) {
	// Check if we've already visited this block to prevent infinite loops
	if visited[block] {
		return
	}
	visited[block] = true

	for _, instr := range block.Instrs {
		switch instr := instr.(type) {
		case *ssa.Alloc:
			// Create bounds for local slices
			if sliceCap, err := extractSliceCapFromAlloc(instr); err == nil {
				bounds := BoundInfo{
					minSafeIndex: 0,
					maxSafeIndex: sliceCap,
					isExact:      true,
				}
				scope.safeBounds[instr] = bounds
			}

		case *ssa.IndexAddr, *ssa.Slice:
			// Process slice access
			ctx.checkSliceAccess(scope, instr)

		case *ssa.If:
			// Handle conditional scoping
			condition, ok := instr.Cond.(*ssa.BinOp)
			if !ok {
				// Process both branches without condition refinement
				if len(instr.Block().Succs) == 2 {
					trueVisited := make(map[*ssa.BasicBlock]bool)
					falseVisited := make(map[*ssa.BasicBlock]bool)
					for k, v := range visited {
						trueVisited[k] = v
						falseVisited[k] = v
					}

					// Process both branches with current scope
					trueScope := ctx.WithScope(scope, func(trueScope *SliceScopeState) {
						ctx.processBlockWithScopeRecursive(trueScope, instr.Block().Succs[0], trueVisited)
					})
					falseScope := ctx.WithScope(scope, func(falseScope *SliceScopeState) {
						ctx.processBlockWithScopeRecursive(falseScope, instr.Block().Succs[1], falseVisited)
					})

					// Merge errors, avoiding duplicates
					ctx.mergeErrors(scope, trueScope, falseScope)
				}
				continue
			}

			// Check if this condition can be statically determined for exact bounds
			isAlwaysTrue, isAlwaysFalse := ctx.isConditionStatic(scope, condition)

			// Process both branches with their respective scoped conditions
			if len(instr.Block().Succs) == 2 {
				// Create new visited maps for each branch to avoid cross-contamination
				trueVisited := make(map[*ssa.BasicBlock]bool)
				falseVisited := make(map[*ssa.BasicBlock]bool)

				// Copy current visited state to both branches
				for k, v := range visited {
					trueVisited[k] = v
					falseVisited[k] = v
				}

				var trueScope, falseScope *SliceScopeState

				// Only process reachable branches
				if !isAlwaysFalse {
					// True branch - condition is true
					trueScope = ctx.WithCondition(scope, condition, true, func(trueScope *SliceScopeState) {
						ctx.processBlockWithScopeRecursive(trueScope, instr.Block().Succs[0], trueVisited)
					})
				} else {
					// Create empty scope for unreachable branch
					trueScope = &SliceScopeState{safeBounds: make(map[ssa.Value]BoundInfo), errors: []*issue.Issue{}}
				}

				if !isAlwaysTrue {
					// False branch - condition is false
					falseScope = ctx.WithCondition(scope, condition, false, func(falseScope *SliceScopeState) {
						ctx.processBlockWithScopeRecursive(falseScope, instr.Block().Succs[1], falseVisited)
					})
				} else {
					// Create empty scope for unreachable branch
					falseScope = &SliceScopeState{safeBounds: make(map[ssa.Value]BoundInfo), errors: []*issue.Issue{}}
				}

				// Merge errors from both branches, avoiding duplicates
				ctx.mergeErrors(scope, trueScope, falseScope)
			}
		}
	}
}

// mergeErrors merges errors from branch scopes into the parent scope, avoiding duplicates
// Only reports errors that would occur in actual execution paths
func (ctx *ScopeContext) mergeErrors(parentScope *SliceScopeState, trueScope *SliceScopeState, falseScope *SliceScopeState) {
	fmt.Printf("MERGE: trueScope has %d errors, falseScope has %d errors\n", len(trueScope.errors), len(falseScope.errors))

	for i, err := range trueScope.errors {
		fmt.Printf("  TRUE[%d]: %s:%s:%s - %s\n", i, err.File, err.Line, err.Col, err.What)
	}

	for i, err := range falseScope.errors {
		fmt.Printf("  FALSE[%d]: %s:%s:%s - %s\n", i, err.File, err.Line, err.Col, err.What)
	}

	// For static analysis, we should only report errors that:
	// 1. Occur in both branches (definite errors), OR
	// 2. Occur in one branch but the other branch is unreachable

	// Create maps for efficient lookup
	trueErrors := make(map[string]*issue.Issue)
	falseErrors := make(map[string]*issue.Issue)

	for _, err := range trueScope.errors {
		key := fmt.Sprintf("%s:%s:%s:%s", err.File, err.Line, err.Col, err.Autofix)
		trueErrors[key] = err
	}

	for _, err := range falseScope.errors {
		key := fmt.Sprintf("%s:%s:%s:%s", err.File, err.Line, err.Col, err.Autofix)
		falseErrors[key] = err
	}

	// Add errors that occur in both branches (definite errors)
	for key, err := range trueErrors {
		if _, existsInFalse := falseErrors[key]; existsInFalse {
			fmt.Printf("MERGE: Adding error that occurs in both branches: %s\n", key)
			// Clear the internal instruction pointer before adding to parent scope
			err.Autofix = ""
			parentScope.errors = append(parentScope.errors, err)
		} else {
			fmt.Printf("MERGE: Adding error from true branch only: %s\n", key)
			// Clear the internal instruction pointer before adding to parent scope
			err.Autofix = ""
			parentScope.errors = append(parentScope.errors, err)
		}
	}

	// Add errors that only occur in false branch
	for key, err := range falseErrors {
		if _, existsInTrue := trueErrors[key]; !existsInTrue {
			fmt.Printf("MERGE: Adding error from false branch only: %s\n", key)
			// Clear the internal instruction pointer before adding to parent scope
			err.Autofix = ""
			parentScope.errors = append(parentScope.errors, err)
		}
	}

	fmt.Printf("MERGE: Final parent scope has %d errors\n", len(parentScope.errors))
}

// runSliceBoundsWithClosures implements the closure-based approach
func runSliceBoundsWithClosures(pass *analysis.Pass) (interface{}, error) {
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		return nil, err
	}

	ctx := &ScopeContext{
		pass:     pass,
		analyzer: pass.Analyzer,
	}

	allErrors := []*issue.Issue{}

	for _, fn := range ssaResult.SSA.SrcFuncs {
		// Create function scope
		fnScope := ctx.WithScope(nil, func(scope *SliceScopeState) {
			// Add function parameters as bounds sources
			for _, param := range fn.Params {
				if isSliceType(param.Type()) {
					bounds := BoundInfo{
						minSafeIndex: -1, // No indices are safe by default for parameters
						maxSafeIndex: -1, // Unknown capacity
						isExact:      false,
					}
					scope.safeBounds[param] = bounds
				}
			}

			// Process function blocks starting from entry block
			// Use a global visited map to avoid processing blocks multiple times
			globalVisited := make(map[*ssa.BasicBlock]bool)
			if len(fn.Blocks) > 0 {
				ctx.processBlockWithScopeRecursive(scope, fn.Blocks[0], globalVisited)
			}
		})

		// Clear internal instruction pointers before adding to final result
		for _, err := range fnScope.errors {
			err.Autofix = ""
		}
		allErrors = append(allErrors, fnScope.errors...)
	}

	if len(allErrors) > 0 {
		return allErrors, nil
	}
	return nil, nil
}
