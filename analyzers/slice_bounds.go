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

func runSliceBounds(pass *analysis.Pass) (interface{}, error) {
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

					// Check if the slice source is a parameter slice
					if param, ok := sliceSource.(*ssa.Parameter); ok && isSliceType(param.Type()) {
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
		for i, block := range ifref.Block().Succs {
			if i == 1 {
				bound = invBound(bound)
				// Adjust value for inverted lowerUnbounded (len(s) < N -> len(s) >= N)
				if originalBound == lowerUnbounded {
					value = value - 1
				}
			}
			var processBlock func(block *ssa.BasicBlock, depth int)
			processBlock = func(block *ssa.BasicBlock, depth int) {
				if depth == maxDepth {
					return
				}
				depth++
				for _, instr := range block.Instrs {
					if _, ok := issues[instr]; ok {
						switch bound {
						case lowerUnbounded:
							// Temporarily add handling for lowerUnbounded case like other bounds
							switch tinstr := instr.(type) {
							case *ssa.IndexAddr:
								if shouldRemoveIssueForBounds(tinstr, binop, bound, value) {
									delete(issues, instr)
								}
							}
						case upperUnbounded, unbounded, upperBounded:
							switch tinstr := instr.(type) {
							case *ssa.Slice:
								if bound == upperBounded {
									lower, upper := extractSliceBounds(tinstr)
									if isSliceInsideBounds(0, value, lower, upper) {
										delete(issues, instr)
									}
								}
							case *ssa.IndexAddr:
								if shouldRemoveIssueForBounds(tinstr, binop, bound, value) {
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
				indexValue, err := extractIntValue(refinstr.Index.String())
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
				return upperUnbounded, value, nil
			case token.LEQ:
				return upperUnbounded, value - 1, nil
			case token.GTR:
				return lowerUnbounded, value, nil
			case token.GEQ:
				return lowerUnbounded, value + 1, nil
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
				return lowerUnbounded, value, nil
			case token.LEQ:
				return lowerUnbounded, value + 1, nil
			case token.GTR:
				return upperUnbounded, value, nil
			case token.GEQ:
				return upperUnbounded, value - 1, nil
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
		l, err := extractIntValue(slice.Low.String())
		if err == nil {
			low = l
		}
	}
	var high int
	if slice.High != nil {
		h, err := extractIntValue(slice.High.String())
		if err == nil {
			high = h
		}
	}
	return low, high
}

func extractIntValue(value string) (int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid value: %s", value)
	}
	if parts[1] != "int" {
		return 0, fmt.Errorf("invalid value: %s", value)
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

func isSliceType(t types.Type) bool {
	if _, ok := t.(*types.Slice); ok {
		return true
	}

	if named, ok := t.(*types.Named); ok {
		if _, ok := named.Underlying().(*types.Slice); ok {
			return true
		}
	}

	return false
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
	indexValue, err := extractIntValue(ia.Index.String())
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
				return true // Unreachable code - condition is false
			}
			return indexValue < exactLength // Check exact bounds
		case upperUnbounded, unbounded:
			if !*conditionResult {
				return true // Unreachable code - condition is false
			}
			return indexValue < exactLength // Check exact bounds
		case upperBounded:
			return *conditionResult && indexValue < exactLength
		}
	}

	// Cannot evaluate condition exactly, fall back to heuristic
	return shouldFallBackToHeuristic(indexValue, bound, value)
}

// processExternalSliceIssue handles bounds checking for external slices (parameters, unknown bounds)
func processExternalSliceIssue(tinstr *ssa.IndexAddr, binop *ssa.BinOp, bound bound, value int) bool {
	indexValue, err := extractIntValue(tinstr.Index.String())
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

// isLocalSlice determines if a slice instruction refers to a locally-created slice
func isLocalSlice(ia *ssa.IndexAddr) bool {
	v := ia.X
	if ct, ok := v.(*ssa.ChangeType); ok {
		v = ct.X
	}
	_, ok := v.(*ssa.Alloc)
	return ok
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
