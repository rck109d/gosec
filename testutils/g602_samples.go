package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG602 - Slice access out of bounds
var SampleCodeG602 = []CodeSample{
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0)

	fmt.Println(s[:3])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0)

	fmt.Println(s[3:])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 16)

	fmt.Println(s[:17])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 16)

	fmt.Println(s[:16])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 16)

	fmt.Println(s[5:17])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 4)

	fmt.Println(s[3])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 4)

	fmt.Println(s[5])

}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0)
	s = make([]byte, 3)

	fmt.Println(s[:3])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0, 4)

	fmt.Println(s[:3])
	fmt.Println(s[3])

}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0, 4)

	fmt.Println(s[:5])
	fmt.Println(s[7])

}
`}, 2, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]byte, 0, 4)
	x := s[:2]
	y := x[:10]
	fmt.Println(y)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]int, 0, 4)
	doStuff(s)
}

func doStuff(x []int) {
	newSlice := x[:10]
	fmt.Println(newSlice)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {

	s := make([]int, 0, 30)
	doStuff(s)
	x := make([]int, 20)
	y := x[10:]
	doStuff(y)
	z := y[5:]
	doStuff(z)
}

func doStuff(x []int) {
	newSlice := x[:10]
	fmt.Println(newSlice)
	newSlice2 := x[:6]
	fmt.Println(newSlice2)
}
`}, 2, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	testMap := make(map[string]any, 0)
	testMap["test1"] = map[string]interface{}{
	"test2": map[string]interface{}{
			"value": 0,
		},
	}
	fmt.Println(testMap)
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		fmt.Println(s[0])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		switch s[0] {
		case 0:
			fmt.Println("zero")
			return
		default:
			fmt.Println(s[0])
			return
		}
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		switch s[0] {
		case 0:
			b := true
			if b == true {
				// Should work for many-levels of nesting when the condition is not on the target slice
				fmt.Println(s[0])
			}
			return
		default:
			fmt.Println(s[0])
			return
		}
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		if len(s) > 1 {
			fmt.Println(s[1])
		}
		fmt.Println(s[0])
	}
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 2)
	fmt.Println(s[1])
	s = make([]byte, 0)
	fmt.Println(s[1])
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		if len(s) > 4 {
			fmt.Println(s[3])
		} else {
			// Should error
			fmt.Println(s[2])
		}
		fmt.Println(s[0])
	}
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]byte, 0)
	if len(s) > 0 {
		fmt.Println("fake test")
	}
	fmt.Println(s[0])
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 16)
	for i := 0; i < 17; i++ {
		s = append(s, i)
	}
	if len(s) < 16 {
		fmt.Println(s[10:16])
	} else {
		fmt.Println(s[3:18])
	}
	fmt.Println(s[0])
	for i := range s {
		fmt.Println(s[i])
	}
}

`}, 0, gosec.NewConfig()},
	// foo, unchecked errors
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	s[0]++
	fmt.Println(s[0])
}
// foo, if GT at boundary OK
`}, 3, gosec.NewConfig()},
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) > 2 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// foo, if GT at boundary-1 ERROR
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) > 1 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, if GT at boundary-2, ERROR
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) > 0 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, if LT error
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 1 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, if LT error
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 2 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, if LT error
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 3 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, if LT error
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 3 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, early return IF LT boundary ERROR
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 2 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 3, gosec.NewConfig()},
	// foo, early return IF LT boundary-1 ERROR
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 1 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 3, gosec.NewConfig()},
	// foo, early return IF LT boundary+1 OK
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 3 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
	// foo, early return IF LT boundary+2 OK
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) < 4 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
	// foo, early return if LTE boundary OK
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) <= 2 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
	// foo, early return if LTE boundary-1 ERROR
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) <= 1 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 3, gosec.NewConfig()},
	// foo, early return if LTE boundary+1 OK
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) <= 3 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
	// foo, early return if LTE boundary+2 OK
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) <= 4 {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
}
