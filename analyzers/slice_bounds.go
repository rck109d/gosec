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
					sliceCap, err := extractSliceCapFromAlloc(instr.String())
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
							break
						case upperUnbounded, unbounded:
							if tinstr, ok := instr.(*ssa.IndexAddr); ok {
								// Handle parameter slices
								if _, ok := tinstr.X.(*ssa.Parameter); ok {
									indexValue, err := extractIntValue(tinstr.Index.String())
									if err != nil || indexValue > value {
										break // problem found, do not delete issue
									}
								}
								// Handle named slice types (ChangeType)
								if _, ok := tinstr.X.(*ssa.ChangeType); ok {
									indexValue, err := extractIntValue(tinstr.Index.String())
									if err != nil || indexValue > value {
										break // problem found, do not delete issue
									}
								}
							}
							delete(issues, instr)
						case upperBounded:
							switch tinstr := instr.(type) {
							case *ssa.Slice:
								lower, upper := extractSliceBounds(tinstr)
								if isSliceInsideBounds(0, value, lower, upper) {
									delete(issues, instr)
								}
							case *ssa.IndexAddr:
								indexValue, err := extractIntValue(tinstr.Index.String())
								if err != nil {
									break
								}
								// For unknown capacity slices with length checks, allow access within validated range
								if value > indexValue {
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

func extractSliceCapFromAlloc(instr string) (int, error) {
	re := regexp.MustCompile(`new \[(\d+)\]*`)
	var sliceCap int
	matches := re.FindAllStringSubmatch(instr, -1)
	if matches == nil {
		return sliceCap, errors.New("no slice cap found")
	}

	if len(matches) > 0 {
		m := matches[0]
		if len(m) > 1 {
			return strconv.Atoi(m[1])
		}
	}

	return 0, errors.New("no slice cap found")
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

	return hasLenCall && hasRangeIndex
}
