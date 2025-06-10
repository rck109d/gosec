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

const maxDepth = 20

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

// Configuration for choosing analysis approach
var useScopeBasedAnalysis = true // Set to true to use the new closure-based approach

func runSliceBounds(pass *analysis.Pass) (interface{}, error) {
	if useScopeBasedAnalysis {
		return runSliceBoundsWithClosures(pass)
	}
	return runSliceBoundsLegacy(pass)
}

func runSliceBoundsLegacy(pass *analysis.Pass) (interface{}, error) {
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		return nil, err
	}

	issues := map[ssa.Instruction]*issue.Issue{}
	ifs := map[ssa.If]*ssa.BinOp{}

	for _, mcall := range ssaResult.SSA.SrcFuncs {
		for _, block := range mcall.DomPreorder() {
			for _, instr := range block.Instrs {
				switch instr := instr.(type) {
				case *ssa.Alloc:
					sliceCap, err := extractSliceCapFromAlloc(instr)
					if err != nil {
						break
					}
					allocRefs := instr.Referrers()
					if allocRefs == nil {
						break
					}
					processAllocSlice := func(slice *ssa.Slice, nodeToTrack ssa.Node) {
						if _, ok := slice.X.(*ssa.Alloc); ok && slice.Parent() != nil {
							l, h := extractSliceBounds(slice)
							newCap := computeSliceNewCap(l, h, sliceCap)
							violations := []ssa.Instruction{}
							trackSliceBounds(0, newCap, nodeToTrack, &violations, ifs)
							for _, s := range violations {
								switch s := s.(type) {
								case *ssa.Slice:
									issue := newIssue(
										pass.Analyzer.Name,
										"slice bounds out of range",
										pass.Fset,
										s.Pos(),
										issue.Low,
										issue.High)
									issues[s] = issue
								case *ssa.IndexAddr:
									issue := newIssue(
										pass.Analyzer.Name,
										"slice index out of range",
										pass.Fset,
										s.Pos(),
										issue.Low,
										issue.High)
									issues[s] = issue
								}
							}
						}
					}

					for _, refInstr := range *allocRefs {
						// Check direct slice
						if slice, ok := refInstr.(*ssa.Slice); ok {
							processAllocSlice(slice, slice)
						}
						// Check ChangeType wrapping slice
						if changeType, ok := refInstr.(*ssa.ChangeType); ok && isSliceType(changeType.Type()) {
							if slice, ok := changeType.X.(*ssa.Slice); ok {
								processAllocSlice(slice, changeType)
							}
						}
					}
				case *ssa.IndexAddr:
					// Unwrap ChangeType if present to get the underlying slice source
					sliceSource := instr.X
					if changeType, ok := sliceSource.(*ssa.ChangeType); ok && isSliceType(changeType.Type()) {
						sliceSource = changeType.X
					}

					var param *ssa.Parameter

					// Check if the slice source is directly a parameter slice
					if p, ok := sliceSource.(*ssa.Parameter); ok && isSliceType(p.Type()) {
						param = p
					} else if unOp, ok := sliceSource.(*ssa.UnOp); ok {
						// Handle indirection through UnOp (like *t0 where t0 stores a parameter)
						if alloc, ok := unOp.X.(*ssa.Alloc); ok {
							// Look for what was stored in this alloc
							refs := alloc.Referrers()
							if refs != nil {
								for _, ref := range *refs {
									if store, ok := ref.(*ssa.Store); ok {
										if p, ok := store.Val.(*ssa.Parameter); ok && isSliceType(p.Type()) {
											param = p
											break
										}
									}
								}
							}
						}
					}

					if param != nil {
						// Skip if this appears to be a range loop (simple heuristic)
						if !isLikelyRangeLoop(param) {
							// Track bounds for parameter slices to detect length conditions
							violations := []ssa.Instruction{}
							trackSliceBounds(0, -1, param, &violations, ifs) // -1 means unknown capacity
							issue := newIssue(
								pass.Analyzer.Name,
								"slice index out of range",
								pass.Fset,
								instr.Pos(),
								issue.Low,
								issue.High)
							issues[instr] = issue
						}
					}
				}
			}
		}
	}

	for ifref, binop := range ifs {
		bound, value, err := extractBinOpBound(binop)
		if err != nil {
			continue
		}
		originalBound := bound

		// Get the successor blocks
		succs := ifref.Block().Succs
		if len(succs) != 2 {
			continue // Only handle simple if-else structures
		}

		for i, block := range succs {
			currentBound := bound
			if i == 1 {
				currentBound = invBound(bound)
				// Adjust value for inverted lowerUnbounded (len(s) < N -> len(s) >= N)
				if originalBound == lowerUnbounded {
					value = value - 1
				}
			}

			// Check if this block is a merge point (has multiple predecessors)
			// Only skip merge points for local slices, not external slices
			isMerge := len(block.Preds) > 1

			var processBlock func(block *ssa.BasicBlock, depth int)
			processBlock = func(block *ssa.BasicBlock, depth int) {
				if depth == maxDepth {
					return
				}
				depth++
				for _, instr := range block.Instrs {
					if _, ok := issues[instr]; ok {
						switch currentBound {
						case lowerUnbounded:
							// Temporarily add handling for lowerUnbounded case like other bounds
							switch tinstr := instr.(type) {
							case *ssa.IndexAddr:
								// For local slices, skip merge points; for external slices, process normally
								if isLocalSlice(tinstr) && isMerge {
									continue
								}
								if shouldRemoveIssueForBounds(tinstr, binop, currentBound, value) {
									delete(issues, instr)
								}
							}
						case upperUnbounded, unbounded, upperBounded:
							switch tinstr := instr.(type) {
							case *ssa.Slice:
								if currentBound == upperBounded {
									lower, upper := extractSliceBounds(tinstr)
									if isSliceInsideBounds(0, value, lower, upper) {
										delete(issues, instr)
									}
								}
							case *ssa.IndexAddr:
								// For local slices, skip merge points; for external slices, process normally
								if isLocalSlice(tinstr) && isMerge {
									continue
								}
								if shouldRemoveIssueForBounds(tinstr, binop, currentBound, value) {
									delete(issues, instr)
								}
							}
						}
					} else if nestedIfInstr, ok := instr.(*ssa.If); ok {
						for _, nestedBlock := range nestedIfInstr.Block().Succs {
							processBlock(nestedBlock, depth)
						}
					}
				}
			}

			processBlock(block, 0)
		}
	}

	foundIssues := []*issue.Issue{}
	for _, issue := range issues {
		foundIssues = append(foundIssues, issue)
	}
	if len(foundIssues) > 0 {
		return foundIssues, nil
	}
	return nil, nil
}

func trackSliceBounds(depth int, sliceCap int, slice ssa.Node, violations *[]ssa.Instruction, ifs map[ssa.If]*ssa.BinOp) {
	if depth == maxDepth {
		return
	}
	depth++
	if violations == nil {
		violations = &[]ssa.Instruction{}
	}

	referrers := slice.Referrers()
	if referrers != nil {
		for _, refinstr := range *referrers {
			switch refinstr := refinstr.(type) {
			case *ssa.Slice:
				checkAllSlicesBounds(depth, sliceCap, refinstr, violations, ifs)
				switch refinstr.X.(type) {
				case *ssa.Alloc, *ssa.Parameter:
					l, h := extractSliceBounds(refinstr)
					newCap := computeSliceNewCap(l, h, sliceCap)
					trackSliceBounds(depth, newCap, refinstr, violations, ifs)
				}
			case *ssa.IndexAddr:
				indexValue, err := extractNumberColonInt(refinstr.Index.String())
				if err == nil && !isSliceIndexInsideBounds(0, sliceCap, indexValue) {
					*violations = append(*violations, refinstr)
				}
			case *ssa.ChangeType:
				// Handle named slice types - track bounds through the ChangeType
				if isSliceType(refinstr.Type()) {
					trackSliceBounds(depth, sliceCap, refinstr, violations, ifs)
				}
			case *ssa.Call:
				if ifref, cond := extractSliceIfLenCondition(refinstr); ifref != nil && cond != nil {
					ifs[*ifref] = cond
				} else {
					parPos := -1
					for pos, arg := range refinstr.Call.Args {
						if a, ok := arg.(*ssa.Slice); ok && a == slice {
							parPos = pos
						}
					}
					if fn, ok := refinstr.Call.Value.(*ssa.Function); ok {
						if len(fn.Params) > parPos && parPos > -1 {
							param := fn.Params[parPos]
							trackSliceBounds(depth, sliceCap, param, violations, ifs)
						}
					}
				}
			}
		}
	}
}

func checkAllSlicesBounds(depth int, sliceCap int, slice *ssa.Slice, violations *[]ssa.Instruction, ifs map[ssa.If]*ssa.BinOp) {
	if depth == maxDepth {
		return
	}
	depth++
	if violations == nil {
		violations = &[]ssa.Instruction{}
	}
	sliceLow, sliceHigh := extractSliceBounds(slice)
	if !isSliceInsideBounds(0, sliceCap, sliceLow, sliceHigh) {
		*violations = append(*violations, slice)
	}
	switch slice.X.(type) {
	case *ssa.Alloc, *ssa.Parameter, *ssa.Slice:
		l, h := extractSliceBounds(slice)
		newCap := computeSliceNewCap(l, h, sliceCap)
		trackSliceBounds(depth, newCap, slice, violations, ifs)
	}

	references := slice.Referrers()
	if references == nil {
		return
	}
	for _, ref := range *references {
		switch s := ref.(type) {
		case *ssa.Slice:
			checkAllSlicesBounds(depth, sliceCap, s, violations, ifs)
			switch s.X.(type) {
			case *ssa.Alloc, *ssa.Parameter:
				l, h := extractSliceBounds(s)
				newCap := computeSliceNewCap(l, h, sliceCap)
				trackSliceBounds(depth, newCap, s, violations, ifs)
			}
		}
	}
}

func extractSliceIfLenCondition(call *ssa.Call) (*ssa.If, *ssa.BinOp) {
	if builtInLen, ok := call.Call.Value.(*ssa.Builtin); ok {
		if builtInLen.Name() == "len" {
			refs := call.Referrers()
			if refs != nil {
				for _, ref := range *refs {
					if binop, ok := ref.(*ssa.BinOp); ok {
						binoprefs := binop.Referrers()
						for _, ref := range *binoprefs {
							if ifref, ok := ref.(*ssa.If); ok {
								return ifref, binop
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

func computeSliceNewCap(l, h, oldCap int) int {
	// If oldCap is -1 (unknown), derived slices are also unknown
	if oldCap == -1 {
		return -1
	}
	if l == 0 && h == 0 {
		return oldCap
	}
	if l > 0 && h == 0 {
		return oldCap - l
	}
	if l == 0 && h > 0 {
		return h
	}
	return h - l
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

func extractBinOpBound(binop *ssa.BinOp) (bound, int, error) {
	if binop.X != nil {
		if x, ok := binop.X.(*ssa.Const); ok {
			value, err := strconv.Atoi(x.Value.String())
			if err != nil {
				return lowerUnbounded, value, err
			}
			switch binop.Op {
			case token.LSS:
				return lowerUnbounded, value, nil // N < len(s) means len(s) > N, so indices 0..N are safe
			case token.LEQ:
				return lowerUnbounded, value - 1, nil // N <= len(s) means len(s) >= N, so indices 0..N-1 are safe
			case token.GTR:
				return upperUnbounded, value - 1, nil // N > len(s) means len(s) < N, so indices 0..N-2 are safe
			case token.GEQ:
				return upperUnbounded, value, nil // N >= len(s) means len(s) <= N, so indices 0..N-1 are safe
			case token.EQL:
				return upperBounded, value, nil
			case token.NEQ:
				return unbounded, value, nil
			}
		}
	}
	if binop.Y != nil {
		if y, ok := binop.Y.(*ssa.Const); ok {
			value, err := strconv.Atoi(y.Value.String())
			if err != nil {
				return lowerUnbounded, value, err
			}
			switch binop.Op {
			case token.LSS:
				return upperUnbounded, value - 1, nil // len(s) < N means indices 0..N-2 are safe
			case token.LEQ:
				return upperUnbounded, value, nil // len(s) <= N means indices 0..N-1 are safe
			case token.GTR:
				return lowerUnbounded, value, nil // len(s) > N means indices 0..N are safe
			case token.GEQ:
				return lowerUnbounded, value - 1, nil // len(s) >= N means indices 0..N-1 are safe
			case token.EQL:
				return upperBounded, value, nil
			case token.NEQ:
				return unbounded, value, nil
			}
		}
	}
	return lowerUnbounded, 0, fmt.Errorf("unable to extract constant from binop")
}

func isSliceIndexInsideBounds(l, h int, index int) bool {
	// If h is -1, it means unknown capacity - we can't determine bounds
	if h == -1 {
		return false // Conservative approach: assume out of bounds for unknown capacity
	}
	return (l <= index && index < h)
}

func isSliceInsideBounds(l, h int, cl, ch int) bool {
	// If h is -1, it means unknown capacity - we can't determine bounds
	if h == -1 {
		return false // Conservative approach: assume out of bounds for unknown capacity
	}
	return (l <= cl && h >= ch) && (l <= ch && h >= cl)
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

// isLikelyRangeLoop uses simple heuristics to detect if a parameter slice is used in a range loop
func isLikelyRangeLoop(param *ssa.Parameter) bool {
	fn := param.Parent()
	if fn == nil {
		return false
	}

	// Simple heuristic: if function has len(param) call and phi with #rangeindex, likely a range loop
	hasLenCall := false
	hasRangeIndex := false

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			// Check for len(param) call
			if call, ok := instr.(*ssa.Call); ok {
				if builtin, ok := call.Call.Value.(*ssa.Builtin); ok {
					if builtin.Name() == "len" && len(call.Call.Args) > 0 {
						if call.Call.Args[0] == param {
							hasLenCall = true
						}
					}
				}
			}
			// Check for range index phi
			if phi, ok := instr.(*ssa.Phi); ok {
				if strings.Contains(phi.String(), "#rangeindex") {
					hasRangeIndex = true
				}
			}
		}
	}

	// Only consider it a range loop if BOTH conditions are met
	// The presence of len() alone (e.g., in defer statements for logging) should not qualify
	return hasLenCall && hasRangeIndex
}

func isLengthConditionRelatedToSlice(binop *ssa.BinOp, param *ssa.Parameter) bool {
	// Check if the binary operation involves len() of the same parameter
	var lenCall *ssa.Call

	// Check if X is a len() call on the parameter
	if call, ok := binop.X.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
			if len(call.Call.Args) > 0 && getSliceSource(call.Call.Args[0]) == param {
				lenCall = call
			}
		}
	}

	// Check if Y is a len() call on the parameter
	if call, ok := binop.Y.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
			if len(call.Call.Args) > 0 && getSliceSource(call.Call.Args[0]) == param {
				lenCall = call
			}
		}
	}

	// If lenCall is found, ensure the condition is related to the slice access
	if lenCall != nil {
		refs := lenCall.Referrers()
		if refs != nil {
			for _, ref := range *refs {
				if binop, ok := ref.(*ssa.BinOp); ok {
					binoprefs := binop.Referrers()
					for _, ref := range *binoprefs {
						if ifref, ok := ref.(*ssa.If); ok {
							// Ensure the if condition is directly related to the slice access
							if ifref.Cond == binop {
								// Check if the slice access is within the same block as the if condition
								for _, instr := range ifref.Block().Instrs {
									if indexAddr, ok := instr.(*ssa.IndexAddr); ok {
										if indexAddr.X == param {
											return true
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return false
}

// checkConditionApplies checks if a binary operation condition applies to a parameter slice
// This checks if the binary operation directly involves len() of the specified parameter
func checkConditionApplies(binop *ssa.BinOp, param *ssa.Parameter) bool {
	// Check if either side of the binary operation is a len() call on the parameter
	if call, ok := binop.X.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
			if len(call.Call.Args) > 0 && getSliceSource(call.Call.Args[0]) == param {
				return true
			}
		}
	}

	if call, ok := binop.Y.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
			if len(call.Call.Args) > 0 && getSliceSource(call.Call.Args[0]) == param {
				return true
			}
		}
	}

	return false
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

// evaluateExactCondition evaluates a len() condition with exact slice bounds
// Returns true if condition is true, false if false, nil if cannot evaluate exactly
func evaluateExactCondition(binop *ssa.BinOp, sliceSource ssa.Value, exactLength int) *bool {
	var lenCall *ssa.Call
	var constValue int
	var hasConstant bool

	// Check if X is a len() call on the slice and Y is a constant
	if call, ok := binop.X.(*ssa.Call); ok {
		if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
			if len(call.Call.Args) > 0 && getSliceSource(call.Call.Args[0]) == sliceSource {
				lenCall = call
				if y, ok := binop.Y.(*ssa.Const); ok {
					if val, err := strconv.Atoi(y.Value.String()); err == nil {
						constValue = val
						hasConstant = true
					}
				}
			}
		}
	}

	// Check if Y is a len() call on the slice and X is a constant
	if lenCall == nil {
		if call, ok := binop.Y.(*ssa.Call); ok {
			if builtin, ok := call.Call.Value.(*ssa.Builtin); ok && builtin.Name() == "len" {
				if len(call.Call.Args) > 0 && getSliceSource(call.Call.Args[0]) == sliceSource {
					lenCall = call
					if x, ok := binop.X.(*ssa.Const); ok {
						if val, err := strconv.Atoi(x.Value.String()); err == nil {
							constValue = val
							hasConstant = true
						}
					}
				}
			}
		}
	}

	if lenCall == nil || !hasConstant {
		return nil // Cannot evaluate exactly
	}

	// Evaluate the condition with exact length
	switch binop.Op {
	case token.LSS: // len(s) < N or N < len(s)
		if binop.X == lenCall {
			result := exactLength < constValue
			return &result
		} else {
			result := constValue < exactLength
			return &result
		}
	case token.LEQ: // len(s) <= N or N <= len(s)
		if binop.X == lenCall {
			result := exactLength <= constValue
			return &result
		} else {
			result := constValue <= exactLength
			return &result
		}
	case token.GTR: // len(s) > N or N > len(s)
		if binop.X == lenCall {
			result := exactLength > constValue
			return &result
		} else {
			result := constValue > exactLength
			return &result
		}
	case token.GEQ: // len(s) >= N or N >= len(s)
		if binop.X == lenCall {
			result := exactLength >= constValue
			return &result
		} else {
			result := constValue >= exactLength
			return &result
		}
	case token.EQL: // len(s) == N or N == len(s)
		result := exactLength == constValue
		return &result
	case token.NEQ: // len(s) != N or N != len(s)
		result := exactLength != constValue
		return &result
	}

	return nil
}

// processLocalSliceIssue handles bounds checking for locally-created slices (exact bounds known)
func processLocalSliceIssue(ia *ssa.IndexAddr, binop *ssa.BinOp, bound bound, value int) bool {
	indexValue, err := extractNumberColonInt(ia.Index.String())
	if err != nil {
		return false
	}
	sliceSource := getSliceSource(ia.X)

	// Try to get exact length from slice instruction if available
	var exactLength int
	if slice, ok := sliceSource.(*ssa.Slice); ok {
		exactLength, err = extractSliceLenFromSlice(slice)
		if err != nil {
			// Fall back to capacity from alloc if slice length extraction fails
			if alloc, ok := slice.X.(*ssa.Alloc); ok {
				exactLength, err = extractSliceCapFromAlloc(alloc)
				if err != nil {
					return shouldFallBackToHeuristic(indexValue, bound, value)
				}
			} else {
				return shouldFallBackToHeuristic(indexValue, bound, value)
			}
		}
	} else if alloc, ok := sliceSource.(*ssa.Alloc); ok {
		// For direct alloc access, use capacity as length
		exactLength, err = extractSliceCapFromAlloc(alloc)
		if err != nil {
			return shouldFallBackToHeuristic(indexValue, bound, value)
		}
	} else {
		return false // Not a local slice
	}

	// Use exact condition evaluation for local slices
	if conditionResult := evaluateExactCondition(binop, sliceSource, exactLength); conditionResult != nil {
		switch bound {
		case lowerUnbounded:
			if !*conditionResult {
				return true // Unreachable code - condition is false, so remove issue
			}
			// If condition is true, check bounds based on what the condition guarantees
			return indexValue <= value // len(s) > value means indices 0..value are safe
		case upperUnbounded, unbounded:
			if !*conditionResult {
				return true // Unreachable code - condition is false, so remove issue
			}
			// If condition is true, check bounds based on what the condition guarantees
			return indexValue < value // len(s) < value means indices 0..value-1 are safe
		case upperBounded:
			// For exact equality, only safe if condition is true AND within bounds
			return *conditionResult && indexValue < value
		}
	}

	// Cannot evaluate condition exactly, fall back to heuristic
	return shouldFallBackToHeuristic(indexValue, bound, value)
}

// processExternalSliceIssue handles bounds checking for external slices (parameters, unknown bounds)
func processExternalSliceIssue(tinstr *ssa.IndexAddr, binop *ssa.BinOp, bound bound, value int) bool {
	indexValue, err := extractNumberColonInt(tinstr.Index.String())
	if err != nil {
		return false
	}

	// Check if the condition actually relates to this specific slice first
	sliceSource := getSliceSource(tinstr.X)
	var param *ssa.Parameter

	if p, ok := sliceSource.(*ssa.Parameter); ok {
		param = p
	} else if changeType, ok := tinstr.X.(*ssa.ChangeType); ok {
		if p, ok := changeType.X.(*ssa.Parameter); ok {
			param = p
		}
	}

	if param == nil {
		return false // Not an external slice parameter
	}

	// Check if condition relates to this slice parameter
	if !isConditionRelatedToExternalSlice(binop, param, bound) {
		return false // Condition doesn't apply to this slice
	}

	// Now check bounds based on the condition type
	switch bound {
	case lowerUnbounded:
		// len(s) > value means indices 0 through value are safe
		return indexValue <= value
	case upperUnbounded:
		// len(s) < value means indices 0 through value-1 are potentially safe
		return indexValue < value
	case upperBounded:
		// len(s) == value means indices 0 through value-1 are safe
		return indexValue < value
	case unbounded:
		// len(s) != value - complex case, be conservative for now
		return false
	}

	return false
}

// isConditionRelatedToExternalSlice checks if a condition applies to an external slice parameter
func isConditionRelatedToExternalSlice(binop *ssa.BinOp, param *ssa.Parameter, bound bound) bool {
	switch bound {
	case lowerUnbounded:
		return checkConditionApplies(binop, param)
	case upperUnbounded, unbounded:
		return isLengthConditionRelatedToSlice(binop, param)
	case upperBounded:
		return checkConditionApplies(binop, param)
	default:
		return false
	}
}

// shouldFallBackToHeuristic provides heuristic bounds checking when exact evaluation fails
func shouldFallBackToHeuristic(indexValue int, bound bound, value int) bool {
	switch bound {
	case upperUnbounded, unbounded:
		return indexValue <= value
	case upperBounded:
		return value > indexValue
	default:
		return false
	}
}

func isSliceType(t types.Type) bool {
	if named, ok := t.(*types.Named); ok {
		t = named.Underlying()
	}
	_, ok := t.(*types.Slice)
	return ok
}

// isLocalSlice determines if a slice instruction refers to a locally-created slice
func isLocalSlice(ia *ssa.IndexAddr) bool {
	v := ia.X
	if ct, ok := v.(*ssa.ChangeType); ok {
		v = ct.X
	}

	// Check if v is directly an Alloc
	if _, ok := v.(*ssa.Alloc); ok {
		return true
	}

	// Check if v is a Slice backed by an Alloc
	if slice, ok := v.(*ssa.Slice); ok {
		if _, ok := slice.X.(*ssa.Alloc); ok {
			return true
		}
	}

	return false
}

// isExternalSlice determines if a slice instruction refers to an external slice (parameter)
func isExternalSlice(ia *ssa.IndexAddr) bool {
	v := ia.X
	if ct, ok := v.(*ssa.ChangeType); ok {
		v = ct.X
	}
	_, ok := v.(*ssa.Parameter)
	return ok
}

// Helper function to determine if an issue should be removed based on bounds checking
func shouldRemoveIssueForBounds(ia *ssa.IndexAddr, binop *ssa.BinOp, bound bound, v int) bool {
	if isLocalSlice(ia) {
		return processLocalSliceIssue(ia, binop, bound, v)
	} else if isExternalSlice(ia) {
		return processExternalSliceIssue(ia, binop, bound, v)
	}
	return false
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

	if !hasBounds {
		// Unknown slice - report error to encourage defensive programming
		ctx.addSliceError(scope, ia, "slice index out of range")
		return
	}

	if bounds.isExact && bounds.minSafeIndex >= 0 && bounds.maxSafeIndex >= bounds.minSafeIndex {
		// Known safe bounds (local slice) - check them precisely
		if indexValue >= bounds.maxSafeIndex || indexValue < bounds.minSafeIndex {
			ctx.addSliceError(scope, ia, "slice index out of range")
		}
	} else {
		// Parameter slice or unknown bounds - encourage defensive programming
		// Functions should check len() before accessing parameter slices
		ctx.addSliceError(scope, ia, "slice index out of range")
	}
}

// checkSliceOperation validates a slice operation
func (ctx *ScopeContext) checkSliceOperation(scope *SliceScopeState, slice *ssa.Slice) {
	low, high := extractSliceBounds(slice)
	sliceSource := getSliceSource(slice.X)
	bounds, hasBounds := scope.safeBounds[sliceSource]

	fmt.Printf("DEBUG: checkSliceOperation: slice=%s, low=%d, high=%d, sliceSource=%s\n",
		slice.String(), low, high, sliceSource.String())

	if hasBounds {
		fmt.Printf("DEBUG: Found bounds for slice source: minSafe=%d, maxSafe=%d, isExact=%t\n",
			bounds.minSafeIndex, bounds.maxSafeIndex, bounds.isExact)
	} else {
		fmt.Printf("DEBUG: No bounds found for slice source\n")
	}

	if !hasBounds {
		// Unknown slice - report error and create new bounds for the result
		fmt.Printf("DEBUG: Reporting error for unknown slice bounds\n")
		ctx.addSliceError(scope, slice, "slice bounds out of range")
		return
	}

	// Check if slice bounds are within known safe bounds
	if bounds.isExact && bounds.minSafeIndex >= 0 && bounds.maxSafeIndex >= bounds.minSafeIndex {
		// Known safe bounds (local slice) - check them precisely
		fmt.Printf("DEBUG: Checking precise bounds for local slice\n")
		if low < bounds.minSafeIndex {
			fmt.Printf("DEBUG: Low bound %d < minSafeIndex %d - reporting error\n", low, bounds.minSafeIndex)
			ctx.addSliceError(scope, slice, "slice bounds out of range")
			return
		}

		if slice.High != nil {
			// Case: s[low:high] - explicit high bound
			fmt.Printf("DEBUG: Explicit high bound case\n")
			if high > bounds.maxSafeIndex {
				fmt.Printf("DEBUG: High bound %d > maxSafeIndex %d - reporting error\n", high, bounds.maxSafeIndex)
				ctx.addSliceError(scope, slice, "slice bounds out of range")
				return
			}
		} else {
			// Case: s[low:] - implicit high bound (goes to end of slice)
			fmt.Printf("DEBUG: Implicit high bound case\n")
			if low > bounds.maxSafeIndex {
				fmt.Printf("DEBUG: Low bound %d > maxSafeIndex %d - reporting error\n", low, bounds.maxSafeIndex)
				ctx.addSliceError(scope, slice, "slice bounds out of range")
				return
			}
		}
	} else {
		// Parameter slice or unknown bounds - encourage defensive programming
		// Functions should check len() before accessing parameter slices
		fmt.Printf("DEBUG: Parameter slice or unknown bounds - reporting error\n")
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

	// Apply the condition to refine bounds
	newBounds := ctx.refineBounds(existing, bound, value, conditionTrue)
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

	switch bound {
	case lowerUnbounded: // len(s) > value
		// len(s) > value means indices 0 through value are definitely safe
		newBounds.minSafeIndex = 0
		newBounds.maxSafeIndex = value
	case upperUnbounded: // len(s) < value
		// len(s) < value means indices 0 through value-1 might be safe
		newBounds.minSafeIndex = 0
		newBounds.maxSafeIndex = value - 1
	case upperBounded: // len(s) == value
		// len(s) == value means indices 0 through value-1 are exactly safe
		newBounds.minSafeIndex = 0
		newBounds.maxSafeIndex = value - 1
		newBounds.isExact = true
	}

	return newBounds
}

// addSliceError adds an error to the current scope
func (ctx *ScopeContext) addSliceError(scope *SliceScopeState, instr ssa.Instruction, message string) {
	fmt.Printf("DEBUG: Adding error: %s at position %s\n", message, ctx.pass.Fset.Position(instr.Pos()))
	issue := newIssue(
		ctx.analyzer.Name,
		message,
		ctx.pass.Fset,
		instr.Pos(),
		issue.Low,
		issue.High,
	)
	scope.errors = append(scope.errors, issue)
}

// evaluateConditionExactly evaluates a condition with known exact length
func (ctx *ScopeContext) evaluateConditionExactly(bound bound, value int, exactLength int) (bool, bool) {
	switch bound {
	case lowerUnbounded: // len(s) > value
		return true, exactLength > value
	case upperUnbounded: // len(s) < value
		return true, exactLength < value
	case upperBounded: // len(s) == value
		return true, exactLength == value
	case unbounded: // len(s) != value
		return true, exactLength != value
	default:
		return false, false
	}
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
		fmt.Printf("DEBUG: Processing instruction: %s (%T)\n", instr.String(), instr)
		switch instr := instr.(type) {
		case *ssa.Alloc:
			// Create bounds for local slices
			if sliceCap, err := extractSliceCapFromAlloc(instr); err == nil {
				fmt.Printf("DEBUG: Found local slice alloc with capacity %d\n", sliceCap)
				bounds := BoundInfo{
					minSafeIndex: 0,
					maxSafeIndex: sliceCap,
					isExact:      true,
				}
				scope.safeBounds[instr] = bounds
			}

		case *ssa.IndexAddr, *ssa.Slice:
			// Check slice access immediately
			fmt.Printf("DEBUG: Found slice access: %s\n", instr.String())
			ctx.checkSliceAccess(scope, instr)

		case *ssa.If:
			// Handle conditional scoping
			condition, ok := instr.Cond.(*ssa.BinOp)
			if !ok {
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

				// True branch
				trueScope := ctx.WithCondition(scope, condition, true, func(trueScope *SliceScopeState) {
					ctx.processBlockWithScopeRecursive(trueScope, instr.Block().Succs[0], trueVisited)
				})

				// False branch
				falseScope := ctx.WithCondition(scope, condition, false, func(falseScope *SliceScopeState) {
					ctx.processBlockWithScopeRecursive(falseScope, instr.Block().Succs[1], falseVisited)
				})

				// Merge errors from both branches
				// But avoid duplicates at the same position
				scope.errors = append(scope.errors, trueScope.errors...)
				for _, falseError := range falseScope.errors {
					// Check if this error already exists in scope.errors
					isDuplicate := false
					for _, existingError := range scope.errors {
						if existingError.Line == falseError.Line &&
							existingError.Col == falseError.Col &&
							existingError.What == falseError.What {
							isDuplicate = true
							break
						}
					}
					if !isDuplicate {
						scope.errors = append(scope.errors, falseError)
					}
				}
			}
		}
	}
}

// runSliceBoundsWithClosures implements the new closure-based approach
func runSliceBoundsWithClosures(pass *analysis.Pass) (interface{}, error) {
	fmt.Printf("DEBUG: runSliceBoundsWithClosures started\n")
	ssaResult, err := getSSAResult(pass)
	if err != nil {
		fmt.Printf("DEBUG: getSSAResult error: %v\n", err)
		return nil, err
	}

	fmt.Printf("DEBUG: SSA has %d SrcFuncs\n", len(ssaResult.SSA.SrcFuncs))
	if len(ssaResult.SSA.SrcFuncs) == 0 {
		// Try to see if there are functions in the program but they're not being classified as SrcFuncs
		for _, pkg := range ssaResult.SSA.Pkg.Prog.AllPackages() {
			fmt.Printf("DEBUG: Package %s has %d members\n", pkg.Pkg.Name(), len(pkg.Members))
			for name, member := range pkg.Members {
				if fn, ok := member.(*ssa.Function); ok {
					fmt.Printf("DEBUG: Member %s is function %s (pos=%v)\n", name, fn.Name(), fn.Pos())
				} else {
					fmt.Printf("DEBUG: Member %s is %T\n", name, member)
				}
			}
		}
	}

	ctx := &ScopeContext{
		pass:     pass,
		analyzer: pass.Analyzer,
	}

	allErrors := []*issue.Issue{}

	for _, fn := range ssaResult.SSA.SrcFuncs {
		fmt.Printf("DEBUG: Processing function %s\n", fn.Name())
		// Create function scope
		fnScope := ctx.WithScope(nil, func(scope *SliceScopeState) {
			// Add function parameters as bounds sources
			for _, param := range fn.Params {
				if isSliceType(param.Type()) {
					fmt.Printf("DEBUG: Found slice parameter %s with type %s\n", param.Name(), param.Type())
					bounds := BoundInfo{
						minSafeIndex: -1, // No indices are safe by default for parameters
						maxSafeIndex: -1, // Unknown capacity
						isExact:      false,
					}
					scope.safeBounds[param] = bounds
				}
			}

			// Process function blocks
			for _, block := range fn.DomPreorder() {
				fmt.Printf("DEBUG: Processing block %s\n", block.String())
				ctx.processBlockWithScope(scope, block)
			}
		})

		fmt.Printf("DEBUG: Function %s generated %d errors\n", fn.Name(), len(fnScope.errors))
		allErrors = append(allErrors, fnScope.errors...)
	}

	if len(allErrors) > 0 {
		return allErrors, nil
	}
	return nil, nil
}

/*
Example of how the closure-based approach naturally handles scope:

func example(s []int) {
    // Function scope: s has unknown bounds (parameter slice)

    if len(s) > 5 {
        // True branch scope: s[0] through s[5] are safe
        println(s[3])  // ✓ Safe access
        println(s[6])  // ✗ Potential out of bounds

        if len(s) > 10 {
            // Nested scope: s[0] through s[10] are safe
            println(s[8])  // ✓ Safe access
        }
        // Back to parent scope: s[0] through s[5] are safe
    } else {
        // False branch scope: s[0] through s[4] might be safe
        println(s[2])  // ✓ Conservative - might be safe
        println(s[6])  // ✗ Definitely out of bounds
    }
    // Back to function scope: unknown bounds again
}

The closure approach:
1. Creates scopes with WithScope/WithCondition
2. Inherits bounds from parent scopes
3. Refines bounds based on conditions
4. Immediately checks accesses and accumulates errors
5. Natural lexical scoping through closures
6. No need for complex two-pass analysis
*/
