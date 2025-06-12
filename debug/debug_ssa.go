package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ssa"
)

func main() {
	src := `
package main

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	s[0]++
	_ = s[0]
}
`

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	files := []*ast.File{f}

	conf := types.Config{
		Importer: importer.Default(),
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}

	pkg, err := conf.Check("main", fset, files, info)
	if err != nil {
		panic(err)
	}

	// Create SSA program
	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)

	// Create SSA package
	ssaPkg := prog.CreatePackage(pkg, files, info, true)

	// Build SSA
	ssaPkg.Build()

	// Print all functions and their instructions
	for _, fn := range ssaPkg.Members {
		if ssaFn, ok := fn.(*ssa.Function); ok {
			fmt.Printf("Function: %s\n", ssaFn.Name())
			for i, block := range ssaFn.Blocks {
				fmt.Printf("  Block %d:\n", i)
				for j, instr := range block.Instrs {
					fmt.Printf("    %d: %v (type: %T)\n", j, instr, instr)

					// Special handling for different instruction types
					switch inst := instr.(type) {
					case *ssa.Alloc:
						fmt.Printf("        Alloc details: %s\n", inst.String())
					case *ssa.MakeSlice:
						fmt.Printf("        MakeSlice details: Len=%v, Cap=%v\n", inst.Len, inst.Cap)
					case *ssa.Slice:
						fmt.Printf("        Slice details: X=%v, Low=%v, High=%v, Max=%v\n", inst.X, inst.Low, inst.High, inst.Max)
					case *ssa.IndexAddr:
						fmt.Printf("        IndexAddr details: X=%v, Index=%v\n", inst.X, inst.Index)
					case *ssa.UnOp:
						fmt.Printf("        UnOp details: Op=%v, X=%v\n", inst.Op, inst.X)
					case *ssa.Store:
						fmt.Printf("        Store details: Addr=%v, Val=%v\n", inst.Addr, inst.Val)
					case *ssa.BinOp:
						fmt.Printf("        BinOp details: Op=%v, X=%v, Y=%v\n", inst.Op, inst.X, inst.Y)
					}
				}
			}
		}
	}
}
