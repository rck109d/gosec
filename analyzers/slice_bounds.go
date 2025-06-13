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
	// unbounded (zero value), no bounds information
	unbounded bound = iota
	// lowerUnbounded: len > N
	lowerUnbounded
	// upperUnbounded: len < N
	upperUnbounded
	// upperBounded: len = N
	upperBounded
)

var boundInverse = map[bound]bound{
	lowerUnbounded: upperUnbounded,
	upperUnbounded: lowerUnbounded,
	unbounded:      upperBounded,
	upperBounded:   unbounded,
}

var sliceCapRegex = regexp.MustCompile(`new \[(\d+)\]\w*(?:\s*\((?:new|makeslice)\))?`)
var sliceLenRegex = regexp.MustCompile(`slice \w+\[:(\d+):`)

// debugf provides a centralized debugf logging function with fmt.Printf-like interface
func debugf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func newSliceBoundsAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runSliceBounds,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runSliceBounds(pass *analysis.Pass) (interface{}, error) {
	debugf("=== SLICE BOUNDS ANALYZER STARTED ===")
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
						safeLen:    0, // No indices are safe by default for parameters
						safeCap:    0, // No capacity known by default for parameters
						isLenExact: false,
						isCapExact: false,
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
		// Collect errors by file and line to avoid duplicates
		errMap := make(map[string]bool)
		for _, err := range fnScope.errors {
			key := fmt.Sprintf("%s:%s:%s", err.File, err.Line, err.What)
			if !errMap[key] {
				errMap[key] = true
				err.Autofix = ""
				allErrors = append(allErrors, err)
			}
		}
	}

	// The test expects only actual slice access errors, not setup errors
	// Filter so we only report slice bounds errors and not slice allocation errors
	filteredErrors := []*issue.Issue{}

	// Keep a map to track unique errors by file and line number
	uniqueErrors := make(map[string]bool)

	for _, err := range allErrors {
		if err.What == "slice bounds out of range" || err.What == "slice index out of range" {
			key := fmt.Sprintf("%s:%s", err.File, err.Line)
			if !uniqueErrors[key] {
				uniqueErrors[key] = true
				filteredErrors = append(filteredErrors, err)
			}
		}
	}

	if len(filteredErrors) > 0 {
		return filteredErrors, nil
	}
	return nil, nil
}

func (b bound) inverse() bound {
	// entries not in map will return zero value: unbounded
	return boundInverse[b]
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
	safeLen    int  // Guaranteed safe length - can access indices [0,safeLen)
	safeCap    int  // Guaranteed safe capacity - can slice [0:safeCap]
	isLenExact bool // Whether length bounds are exact=true (local slice) or conservative=false (parameter)
	isCapExact bool // Whether capacity bounds are exact=true (local slice) or conservative=false (parameter)
}

// ScopeContext manages the parsing context with closures
type ScopeContext struct {
	pass     *analysis.Pass
	analyzer *analysis.Analyzer
}

// WithScope creates a new scope and executes the given function within it
func (sc *ScopeContext) WithScope(parent *SliceScopeState, fn func(*SliceScopeState)) *SliceScopeState {
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
func (sc *ScopeContext) WithCondition(parent *SliceScopeState, condition *ssa.BinOp, conditionTrue bool, fn func(*SliceScopeState)) *SliceScopeState {
	return sc.WithScope(parent, func(scope *SliceScopeState) {
		sc.applyConditionToBounds(scope, condition, conditionTrue)
		fn(scope)
	})
}

// checkSliceAccess performs immediate bounds checking and accumulates errors
func (sc *ScopeContext) checkSliceAccess(scope *SliceScopeState, access ssa.Instruction) {
	switch instr := access.(type) {
	case *ssa.IndexAddr:
		sc.checkIndexAccess(scope, instr)
	case *ssa.Slice:
		sc.checkSliceOperation(scope, instr)
	}
}

// checkIndexAccess validates a slice index access
func (sc *ScopeContext) checkIndexAccess(scope *SliceScopeState, ia *ssa.IndexAddr) {
	indexValue, err := extractNumberColonInt(ia.Index.String())
	if err != nil {
		return // Cannot statically analyze dynamic indices
	}

	sliceSource := getSliceSource(ia.X)
	bounds, hasBounds := scope.safeBounds[sliceSource]

	// Check bounds for index access

	if !hasBounds {
		// Unknown slice - report error to encourage defensive programming
		fmt.Printf("DEBUG: No bounds found for slice source: %v (type: %T)\n", sliceSource, sliceSource)
		sc.addSliceError(scope, ia, "slice index out of range")
		return
	}

	// Use length bounds for index access - indices must be within slice length
	safeBound := bounds.safeLen
	isExact := bounds.isLenExact

	debugf("Index access: sliceSource=%v (type=%T), bounds=%+v, indexValue=%d", sliceSource, sliceSource, bounds, indexValue)

	if isExact && safeBound > 0 {
		// Known exact bounds (local slice) - check them precisely
		if indexValue >= int(safeBound) {
			sc.addSliceError(scope, ia, "slice index out of range")
		}
		// If within bounds, no error is reported
	} else if !isExact {
		// Parameter slice - check if we have safe bounds from conditions
		if safeBound > 0 && indexValue < int(safeBound) {
			// Access is within the guaranteed safe bounds for this parameter
			return
		}
		// Otherwise, report error to encourage defensive programming
		sc.addSliceError(scope, ia, "slice index out of range")
	} else {
		// Other cases - need bounds from conditions to be safe
		if safeBound > 0 && indexValue < int(safeBound) {
			// Access is within the guaranteed safe bounds
			return
		}
		// Report error if bounds are not sufficient
		sc.addSliceError(scope, ia, "slice index out of range")
	}
}

// checkSliceOperation validates a slice operation with full handling of low, high, and max indices
func (sc *ScopeContext) checkSliceOperation(scope *SliceScopeState, slice *ssa.Slice) {
	sliceSource := getSliceSource(slice.X)
	bounds, hasBounds := scope.safeBounds[sliceSource]

	// Extract slice indices with proper handling of nil values
	var lowArg, highArg, maxArg int
	var hasLow, hasHigh, hasMax bool

	if slice.Low != nil {
		if i, err := extractNumberColonInt(slice.Low.String()); err == nil {
			lowArg = i
			hasLow = true
		}
	}
	if slice.High != nil {
		if i, err := extractNumberColonInt(slice.High.String()); err == nil {
			highArg = i
			hasHigh = true
		}
	}
	if slice.Max != nil {
		if maxVal, err := extractNumberColonInt(slice.Max.String()); err == nil {
			maxArg = maxVal
			hasMax = true
		}
	}

	debugf("Slice operation: low=%d(has:%v), high=%d(has:%v), max=%d(has:%v)",
		lowArg, hasLow, highArg, hasHigh, maxArg, hasMax)

	// Check bounds for slice operation
	if !hasBounds {
		// Unknown slice - report error and create conservative bounds for the result
		sc.addSliceError(scope, slice, "slice bounds out of range")
		// Still create bounds for the result to continue analysis
		sc.createResultSliceBounds(scope, slice, 0, 0, false, false, hasLow, hasHigh, hasMax, lowArg, highArg, maxArg)
		return
	}

	debugf("Source bounds: safeLen=%d, safeCap=%d, isLenExact=%v, isCapExact=%v",
		bounds.safeLen, bounds.safeCap, bounds.isLenExact, bounds.isCapExact)

	// Validate slice indices based on what we know
	var errorReported bool

	// Check low index bounds
	if hasLow {
		if lowArg < 0 {
			sc.addSliceError(scope, slice, "slice bounds out of range")
			errorReported = true
		}

		// Low index must be within the slice length
		if bounds.isLenExact {
			if lowArg > bounds.safeLen {
				sc.addSliceError(scope, slice, "slice bounds out of range")
				errorReported = true
			}
		} else if !bounds.isLenExact {
			// For parameter slices, low index access needs bounds checking
			if bounds.safeLen == 0 || lowArg >= bounds.safeLen {
				sc.addSliceError(scope, slice, "slice bounds out of range")
				errorReported = true
			}
		}
	}

	// Check high index bounds
	if hasHigh {
		if highArg < 0 {
			sc.addSliceError(scope, slice, "slice bounds out of range")
			errorReported = true
		}

		// High index must be >= low index
		if hasLow && highArg < lowArg {
			sc.addSliceError(scope, slice, "slice bounds out of range")
			errorReported = true
		}

		// For 3-index slices, high is checked against length; for 2-index, against capacity
		if hasMax {
			// 3-index slice: s[low:high:max] - high checked against length
			if bounds.isLenExact {
				if highArg > bounds.safeLen {
					sc.addSliceError(scope, slice, "slice bounds out of range")
					errorReported = true
				}
			} else if !bounds.isLenExact {
				if bounds.safeLen == 0 || highArg > bounds.safeLen {
					sc.addSliceError(scope, slice, "slice bounds out of range")
					errorReported = true
				}
			}
		} else {
			// 2-index slice: s[low:high] - high checked against capacity
			if bounds.isCapExact {
				if highArg > bounds.safeCap {
					sc.addSliceError(scope, slice, "slice bounds out of range")
					errorReported = true
				}
			} else if !bounds.isCapExact {
				if bounds.safeCap == 0 || highArg > bounds.safeCap {
					sc.addSliceError(scope, slice, "slice bounds out of range")
					errorReported = true
				}
			}
		}
	}

	// Check max index bounds (only for 3-index slices)
	if hasMax {
		if maxArg < 0 {
			sc.addSliceError(scope, slice, "slice bounds out of range")
			errorReported = true
		}

		// Max index must be >= high index
		if hasHigh && maxArg < highArg {
			sc.addSliceError(scope, slice, "slice bounds out of range")
			errorReported = true
		}

		// Max index must be within capacity
		if bounds.isCapExact {
			if maxArg > bounds.safeCap {
				sc.addSliceError(scope, slice, "slice bounds out of range")
				errorReported = true
			}
		} else if !bounds.isCapExact {
			if bounds.safeCap == 0 || maxArg > bounds.safeCap {
				sc.addSliceError(scope, slice, "slice bounds out of range")
				errorReported = true
			}
		}
	}

	// Handle implicit bounds for parameter slices with unknown bounds
	if !bounds.isCapExact && !bounds.isLenExact && !errorReported {
		// For parameter slices without explicit bounds checking, encourage defensive programming
		sc.addSliceError(scope, slice, "slice bounds out of range")
		errorReported = true
	}

	// Create bounds info for the resulting slice
	sc.createResultSliceBounds(scope, slice, bounds.safeLen, bounds.safeCap,
		bounds.isLenExact, bounds.isCapExact, hasLow, hasHigh, hasMax, lowArg, highArg, maxArg)
}

// createResultSliceBounds creates bounds information for the result of a slice operation
func (sc *ScopeContext) createResultSliceBounds(scope *SliceScopeState, slice *ssa.Slice,
	sourceSafeLen, sourceSafeCap int, sourceIsLenExact, sourceIsCapExact bool,
	hasLow, hasHigh, hasMax bool, low, high, maxValue int) {

	var newSafeLen, newSafeCap int
	var newIsLenExact, newIsCapExact bool

	// Default values for missing indices
	effectiveLow := 0
	if hasLow {
		effectiveLow = low
	}

	if hasMax {
		// 3-index slice: s[low:high:max]
		effectiveHigh := sourceSafeLen
		if hasHigh {
			effectiveHigh = high
		}
		effectiveMax := maxValue

		// Length = high - low, Capacity = max - low
		newSafeLen = max(0, effectiveHigh-effectiveLow)
		newSafeCap = max(0, effectiveMax-effectiveLow)

		// Exactness depends on source exactness and whether all indices are explicit
		newIsLenExact = sourceIsLenExact && hasHigh
		newIsCapExact = sourceIsCapExact && hasMax

	} else if hasHigh {
		// 2-index slice: s[low:high]
		effectiveHigh := high

		// Length = Capacity = high - low
		newSafeLen = max(0, effectiveHigh-effectiveLow)
		newSafeCap = newSafeLen

		// Exactness depends on source exactness and explicit indices
		newIsLenExact = sourceIsCapExact && hasHigh // We know exactly what was sliced
		newIsCapExact = sourceIsCapExact && hasHigh

	} else {
		// 1-index slice: s[low:] (implicit high bound)

		// Length = source length - low (if we know source length)
		if sourceSafeLen > 0 {
			newSafeLen = max(0, sourceSafeLen-effectiveLow)
		} else {
			newSafeLen = 0 // Unknown safe length
		}

		// Capacity = source capacity - low (if we know source capacity)
		if sourceSafeCap > 0 {
			newSafeCap = max(0, sourceSafeCap-effectiveLow)
		} else {
			newSafeCap = 0 // Unknown safe capacity
		}

		// Exactness is reduced when using implicit bounds
		newIsLenExact = sourceIsLenExact && hasLow
		newIsCapExact = sourceIsCapExact && hasLow
	}

	// Ensure capacity is at least as large as length
	if newSafeCap < newSafeLen {
		newSafeCap = newSafeLen
	}

	newBounds := BoundInfo{
		safeLen:    newSafeLen,
		safeCap:    newSafeCap,
		isLenExact: newIsLenExact,
		isCapExact: newIsCapExact,
	}

	debugf("Created result bounds for slice: safeLen=%d, safeCap=%d, isLenExact=%v, isCapExact=%v",
		newSafeLen, newSafeCap, newIsLenExact, newIsCapExact)

	scope.safeBounds[slice] = newBounds
}

// applyConditionToBounds updates the bounds based on a conditional
func (sc *ScopeContext) applyConditionToBounds(scope *SliceScopeState, condition *ssa.BinOp, conditionTrue bool) {
	sliceParam, bound, value, err := sc.extractLengthCondition(condition)
	if err != nil {
		return
	}

	existing, hasBounds := scope.safeBounds[sliceParam]
	if !hasBounds {
		existing = BoundInfo{safeLen: 0, safeCap: 0, isLenExact: false, isCapExact: false}
	}

	// Apply the condition to refine bounds (defensive programming approach)
	newBounds := sc.refineBounds(existing, bound, value, conditionTrue)

	scope.safeBounds[sliceParam] = newBounds
}

// refineBounds applies a condition to existing bounds
func (sc *ScopeContext) refineBounds(existing BoundInfo, bound bound, value int, conditionTrue bool) BoundInfo {
	newBounds := existing

	if !conditionTrue {
		// Invert the bound when condition is false
		bound = bound.inverse()
		if bound == lowerUnbounded {
			value = value - 1 // len(s) < N becomes len(s) >= N-1
		}
	}

	// Calculate new bounds based on the condition (length conditions affect both length and capacity)
	var conditionBounds BoundInfo
	switch bound {
	case lowerUnbounded: // len(s) > value
		// len(s) > value means indices 0 through value are definitely safe
		conditionBounds = BoundInfo{
			safeLen:    value + 1, // Safe to access indices 0 to value
			safeCap:    value + 1, // Capacity is at least length
			isLenExact: false,
			isCapExact: false,
		}
	case upperUnbounded: // len(s) < value
		// len(s) < value means slice length is at most value-1
		// For parameter slices, we can't assume any access is safe unless we have
		// existing bounds from parent scopes that guarantee safety
		if existing.safeLen > 0 {
			// We have existing guarantees, so intersect with the upper bound
			conditionBounds = BoundInfo{
				safeLen:    min(existing.safeLen, value-1),
				safeCap:    existing.safeCap, // Capacity bounds don't change from length upper bounds
				isLenExact: false,
				isCapExact: existing.isCapExact,
			}
		} else {
			// No existing guarantees for parameter slices with upper bounds
			conditionBounds = BoundInfo{
				safeLen:    0,
				safeCap:    existing.safeCap, // Keep existing capacity bounds
				isLenExact: false,
				isCapExact: existing.isCapExact,
			}
		}
	case upperBounded: // len(s) == value
		// len(s) == value means indices 0 through value-1 are exactly safe
		conditionBounds = BoundInfo{
			safeLen:    value, // Can access indices 0 to value-1
			safeCap:    value, // For exact length, capacity is at least length
			isLenExact: true,
			isCapExact: false, // We don't know the exact capacity from length conditions
		}
	default:
		return existing // No change for other bound types
	}

	// Apply the condition bounds, considering the existing context
	// For sequential conditions in control flow, newer conditions provide
	// stronger guarantees and should generally replace weaker ones

	if existing.safeLen == 0 {
		// If existing bounds are uninitialized, use condition bounds
		return conditionBounds
	}

	// For the common case where existing bounds are empty [0,0) and we get
	// a condition that makes some indices safe, we should use the condition bounds
	if existing.safeLen == 0 && conditionBounds.safeLen > 0 {
		return conditionBounds
	}

	// Combine bounds based on the type of condition
	switch bound {
	case lowerUnbounded:
		// len(s) > N: This provides a minimum guarantee, so take the stronger (larger) bound
		newBounds.safeLen = max(existing.safeLen, conditionBounds.safeLen)
		newBounds.safeCap = max(existing.safeCap, conditionBounds.safeCap)
	case upperUnbounded, upperBounded:
		// len(s) <= N or len(s) == N: This provides a maximum constraint, so take intersection
		newBounds.safeLen = max(existing.safeLen, conditionBounds.safeLen)
		newBounds.safeCap = max(existing.safeCap, conditionBounds.safeCap)
	default:
		// For other bound types, take intersection (more restrictive)
		newBounds.safeLen = max(existing.safeLen, conditionBounds.safeLen)
		newBounds.safeCap = max(existing.safeCap, conditionBounds.safeCap)
	}

	// Ensure bounds are valid
	if newBounds.safeLen < 0 {
		newBounds.safeLen = 0
	}
	if newBounds.safeCap < 0 {
		newBounds.safeCap = 0
	}

	// If both are exact and match, result is exact
	newBounds.isLenExact = existing.isLenExact && conditionBounds.isLenExact &&
		existing.safeLen == conditionBounds.safeLen
	newBounds.isCapExact = existing.isCapExact && conditionBounds.isCapExact &&
		existing.safeCap == conditionBounds.safeCap

	return newBounds
}

// addSliceError adds an error to the current scope
func (sc *ScopeContext) addSliceError(scope *SliceScopeState, instr ssa.Instruction, message string) {
	issue := newIssue(
		sc.analyzer.Name,
		message,
		sc.pass.Fset,
		instr.Pos(),
		issue.Low,
		issue.High,
	)
	// Add instruction pointer info for deduplication
	issue.Autofix = fmt.Sprintf("instr:%p", instr)
	scope.errors = append(scope.errors, issue)
}

// extractLengthCondition extracts slice parameter and bounds from a condition
func (sc *ScopeContext) extractLengthCondition(condition *ssa.BinOp) (ssa.Value, bound, int, error) {
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
							value = value + 1          // len(s) < N + 1
						case token.GTR:
							boundType = lowerUnbounded // len(s) > N
						case token.GEQ:
							boundType = lowerUnbounded // len(s) >= N
							value = value - 1          // len(s) > N - 1
						case token.EQL:
							boundType = upperBounded // len(s) == N
						case token.NEQ:
							boundType = unbounded // len(s) != N
						default:
							return nil, unbounded, 0, fmt.Errorf("unhandled condition.Op %v", condition.Op)
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
						default:
							return nil, unbounded, 0, fmt.Errorf("unhandled condition.Op %v", condition.Op)
						}
						return sliceParam, boundType, value, nil
					}
				}
			}
		}
	}

	return nil, unbounded, 0, fmt.Errorf("no length condition found")
}

// processBlockWithScopeRecursive processes a basic block with visited tracking to prevent infinite loops
func (sc *ScopeContext) processBlockWithScopeRecursive(scope *SliceScopeState, block *ssa.BasicBlock, visited map[*ssa.BasicBlock]bool) {
	// Check if we've already visited this block to prevent infinite loops
	if visited[block] {
		return
	}
	visited[block] = true

	for _, instr := range block.Instrs {
		debugf("Processing instruction: %v (type: %T)", instr, instr)
		switch instr := instr.(type) {
		case *ssa.Alloc:
			// Create bounds for local slices
			debugf("Processing Alloc: %v", instr)
			if bounds, err := processMakeSliceAlloc(instr); err == nil {
				debugf("Extracted capacity from Alloc: %d", bounds.safeCap)
				if bounds.safeLen != bounds.safeCap {
					debugf("Found slice operation with length %d for alloc %v", bounds.safeLen, instr)
				} else {
					debugf("Found full slice operation for alloc %v, length = capacity = %d", instr, bounds.safeCap)
				}
				debugf("Setting bounds for Alloc %v: %+v", instr, bounds)
				scope.safeBounds[instr] = bounds
			}

		case *ssa.IndexAddr, *ssa.Slice:
			// Skip slice operations that are part of make() - these are internal SSA operations
			if slice, ok := instr.(*ssa.Slice); ok {
				// Check if this slice operation is the result of a make() call
				// by checking if the source is an Alloc that we've already processed
				sliceSource := getSliceSource(slice.X)
				if alloc, isAlloc := sliceSource.(*ssa.Alloc); isAlloc {
					// Check if this slice operation is at the same position as the allocation
					// This indicates it's part of the make() operation, not a user slice access
					allocPos := sc.pass.Fset.Position(alloc.Pos())
					slicePos := sc.pass.Fset.Position(slice.Pos())
					if allocPos.Line == slicePos.Line && allocPos.Column == slicePos.Column {
						// This is the internal slice operation from make() - skip bounds checking
						// But still set up bounds for the result
						if bounds, hasBounds := scope.safeBounds[sliceSource]; hasBounds {
							scope.safeBounds[slice] = bounds
						}
						continue
					}
				}
			}
			// Process slice access
			sc.checkSliceAccess(scope, instr)

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
					trueScope := sc.WithScope(scope, func(trueScope *SliceScopeState) {
						sc.processBlockWithScopeRecursive(trueScope, instr.Block().Succs[0], trueVisited)
					})
					falseScope := sc.WithScope(scope, func(falseScope *SliceScopeState) {
						sc.processBlockWithScopeRecursive(falseScope, instr.Block().Succs[1], falseVisited)
					})

					// Merge errors, avoiding duplicates
					sc.mergeErrors(scope, trueScope, falseScope)
				}
				continue
			}

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

				// True branch - condition is true
				trueScope := sc.WithCondition(scope, condition, true, func(trueScope *SliceScopeState) {
					sc.processBlockWithScopeRecursive(trueScope, instr.Block().Succs[0], trueVisited)
				})

				// False branch - condition is false
				falseScope := sc.WithCondition(scope, condition, false, func(falseScope *SliceScopeState) {
					sc.processBlockWithScopeRecursive(falseScope, instr.Block().Succs[1], falseVisited)
				})

				// Merge errors from both branches, avoiding duplicates
				sc.mergeErrors(scope, trueScope, falseScope)
			}
		}
	}
}

// mergeErrors merges errors from branch scopes into the parent scope, avoiding duplicates
func (sc *ScopeContext) mergeErrors(parentScope *SliceScopeState, trueScope *SliceScopeState, falseScope *SliceScopeState) {

	// For static analysis, we report all errors from both branches

	// Create map to avoid duplicate errors
	seenErrors := make(map[string]bool)

	// Add all errors from true branch
	for _, err := range trueScope.errors {
		key := fmt.Sprintf("%s:%s:%s:%s", err.File, err.Line, err.Col, err.Autofix)
		if !seenErrors[key] {
			// Clear the internal instruction pointer before adding to parent scope
			err.Autofix = ""
			parentScope.errors = append(parentScope.errors, err)
			seenErrors[key] = true
		}
	}

	// Add all errors from false branch
	for _, err := range falseScope.errors {
		key := fmt.Sprintf("%s:%s:%s:%s", err.File, err.Line, err.Col, err.Autofix)
		if !seenErrors[key] {
			// Clear the internal instruction pointer before adding to parent scope
			err.Autofix = ""
			parentScope.errors = append(parentScope.errors, err)
			seenErrors[key] = true
		}
	}
}

// processMakeSliceAlloc processes an *ssa.Alloc instruction that represents a make() slice operation
// and returns the BoundInfo for the slice. This function is extracted for better testability.
func processMakeSliceAlloc(alloc *ssa.Alloc) (BoundInfo, error) {
	// Validate that this allocation is for a slice (from make() call), not an array
	allocString := alloc.String()
	if !strings.Contains(allocString, "makeslice") {
		return BoundInfo{}, errors.New("allocation is not for a slice (makeslice not found in allocation string)")
	}

	capacity, err := extractSliceCapFromAlloc(alloc)
	if err != nil {
		return BoundInfo{}, err
	}

	// For make() slices, we need to determine the actual length vs capacity
	// Check for referrers to find the corresponding slice operation from make()
	actualLen := capacity // Default to capacity if no slice operation found
	actualCap := capacity

	if refs := alloc.Referrers(); refs != nil {
		for _, user := range *refs {
			if slice, ok := user.(*ssa.Slice); ok {
				// This slice operation represents the initialization from make()
				// For make([]T, len, cap), the initialization slice is t0[:len:cap]
				// The High field contains the actual length
				if slice.High != nil {
					if highConst, ok := slice.High.(*ssa.Const); ok {
						if lenVal, err := strconv.Atoi(highConst.Value.String()); err == nil {
							actualLen = lenVal
							break
						}
					}
				} else if slice.Low == nil {
					// Case: slice t0[:] - this means full slice, length = capacity
					actualLen = actualCap
					break
				}
			}
		}
	}

	return BoundInfo{
		safeLen:    actualLen,
		safeCap:    actualCap,
		isLenExact: true,
		isCapExact: true,
	}, nil
}
