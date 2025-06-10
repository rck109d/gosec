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
	// foo, GTE boundary OK - len(s) >= 3 means s[2] is safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) >= 3 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// foo, GTE boundary ERROR - len(s) >= 2 means s[2] is NOT safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) >= 2 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, GTE boundary-1 ERROR - len(s) >= 1 means s[2] is NOT safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) >= 1 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// foo, GTE boundary+1 OK - len(s) >= 4 means s[2] is safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if len(s) >= 4 {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 3 < len(s) means s[2] is safe (same as len(s) > 3)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 3 < len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 2 < len(s) means s[2] is safe (same as len(s) > 2, means len >= 3)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 2 < len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 1 < len(s) means s[2] is NOT safe (same as len(s) > 1, means len >= 2)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 1 < len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// Left-hand constant: 3 <= len(s) means s[2] is safe (same as len(s) >= 3)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 3 <= len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 2 <= len(s) means s[2] is NOT safe (same as len(s) >= 2)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 2 <= len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// Left-hand constant: 3 > len(s) means len(s) < 3, early return should make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 3 > len(s) {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 2 > len(s) means len(s) < 2, early return should NOT make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 2 > len(s) {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 3, gosec.NewConfig()},
	// Left-hand constant: 3 >= len(s) means len(s) <= 3, early return should make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 3 >= len(s) {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 2 >= len(s) means len(s) <= 2, early return SHOULD make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 2 >= len(s) {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 1 >= len(s) means len(s) <= 1, early return should NOT make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 1 >= len(s) {
		return
	}
	s[2]++
	fmt.Println(s[2])
}
`}, 3, gosec.NewConfig()},
	// Left-hand constant: 3 == len(s), guarded access should make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 3 == len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 0, gosec.NewConfig()},
	// Left-hand constant: 2 == len(s), guarded access should NOT make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 2 == len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// Left-hand constant: 1 == len(s), guarded access should NOT make s[2] safe
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	foo(s)
}

func foo(s []int) {
	if 1 == len(s) {
		s[2]++
		fmt.Println(s[2])
	}
}
`}, 3, gosec.NewConfig()},
	// Named slice type - should catch out of bounds access
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	fmt.Println(s[6]) // out of bounds
}
`}, 1, gosec.NewConfig()},
	// Named slice type - should be safe
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	fmt.Println(s[4]) // safe
}
`}, 0, gosec.NewConfig()},
	// Named slice type as parameter - should catch out of bounds without length check
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	f(s)
}

func f(s MySlice) {
	fmt.Println(s[10]) // potential out of bounds
}
`}, 1, gosec.NewConfig()},
	// Named slice type as parameter - should be safe with length check
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	f(s)
}

func f(s MySlice) {
	if len(s) > 10 {
		fmt.Println(s[10]) // safe with length check
	}
}
`}, 0, gosec.NewConfig()},
	// Named slice type - slice operations
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	fmt.Println(s[:6]) // out of bounds slice
}
`}, 1, gosec.NewConfig()},
	// Named slice type - safe slice operations
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	fmt.Println(s[:5]) // safe slice
}
`}, 0, gosec.NewConfig()},
	// Multiple levels of named types
	{[]string{`
package main

import "fmt"

type BaseSlice []int
type MySlice BaseSlice

func main() {
	var s MySlice = make([]int, 3)
	fmt.Println(s[5]) // out of bounds
}
`}, 1, gosec.NewConfig()},
	// Named slice type with length validation - early return pattern
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	f(s)
}

func f(s MySlice) {
	if len(s) < 3 {
		return
	}
	fmt.Println(s[2]) // safe after length check
}
`}, 0, gosec.NewConfig()},
	// Named slice type with insufficient length validation
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 5)
	f(s)
}

func f(s MySlice) {
	if len(s) < 2 {
		return
	}
	fmt.Println(s[2]) // unsafe - need len >= 3 for s[2]
}
`}, 1, gosec.NewConfig()},
	// Range statement should NOT trigger slice index out of range
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 5)
	for i, v := range s {
		fmt.Println(i, v)
	}
}
`}, 0, gosec.NewConfig()},
	// Range statement on parameter slice should NOT trigger slice index out of range
	{[]string{`
package main

import "fmt"

func processSlice(s []int) {
	for _, v := range s {
		fmt.Println(v)
	}
}

func main() {
	s := make([]int, 5)
	processSlice(s)
}
`}, 0, gosec.NewConfig()},
	// Range statement on named slice type should NOT trigger slice index out of range
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make(MySlice, 5)
	for _, v := range s {
		fmt.Println(v)
	}
}
`}, 0, gosec.NewConfig()},
	// Function accepting slice parameter accessing index 0 without bounds check
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 5)
	foo(s)
}

func foo(s []int) {
	fmt.Println(s[0]) // potential out of bounds - no length check
}
`}, 1, gosec.NewConfig()},
	// Package variable condition with unguarded slice access
	{[]string{`
package main

import "fmt"

var shouldProcess bool = true

func main() {
	s := make([]int, 5)
	foo(s)
}

func foo(s []int) {
	if shouldProcess {
		fmt.Println(s[10]) // out of bounds access inside unrelated condition
	}
}
`}, 1, gosec.NewConfig()},
	// Function with len() call for metrics but unguarded slice access (mimics real-world scenario)
	{[]string{`
package main

import "fmt"

func main() {
	cacheEntries := make([]*string, 5)
	updateCache(cacheEntries)
}

func updateCache(cacheEntriesToUpdate []*string) {
	defer func() {
		// len() used in metrics/logging - unrelated to bounds checking
		fmt.Printf("processed %d entries", len(cacheEntriesToUpdate))
	}()
	
	if true { // some unrelated condition
		entry := cacheEntriesToUpdate[0] // potential out of bounds - no length check
		fmt.Printf("processing entry: %v", entry)
	}
}
`}, 1, gosec.NewConfig()},
}
