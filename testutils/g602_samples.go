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
`}, 1, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
	// foo, if GT at boundary OK
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
`}, 2, gosec.NewConfig()},
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
	// Local named slice type - safe access within bounds
	{[]string{`
package main

import "fmt"

type LocalSlice []int

func main() {
	var s LocalSlice = make([]int, 3)
	fmt.Println(s[2]) // safe - within bounds
}
`}, 0, gosec.NewConfig()},
	// Local named slice type - unsafe access out of bounds
	{[]string{`
package main

import "fmt"

type LocalSlice []int

func main() {
	var s LocalSlice = make([]int, 3)
	fmt.Println(s[5]) // out of bounds
}
`}, 1, gosec.NewConfig()},
	// Local named slice type with length condition - should be safe
	{[]string{`
package main

import "fmt"

type LocalSlice []int

func main() {
	var s LocalSlice = make([]int, 3)
	if len(s) > 2 {
		fmt.Println(s[2]) // should be safe when len(s) > 2
	}
}
`}, 0, gosec.NewConfig()},
	// Multiple levels of named types - local allocation
	{[]string{`
package main

import "fmt"

type BaseSlice []int
type DerivedSlice BaseSlice

func main() {
	var s DerivedSlice = make([]int, 2)
	fmt.Println(s[1]) // safe
	fmt.Println(s[3]) // out of bounds
}
`}, 1, gosec.NewConfig()},
	// 3-index slice operations - systematic test matrix
	// Case 1: primitive, low=0, low<high, high<max, max<cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:2:8]) // valid: all bounds respected
}
`}, 0, gosec.NewConfig()},
	// Case 2: primitive, low=0, low<high, high<max, max=cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:2:10]) // valid: max=cap
}
`}, 0, gosec.NewConfig()},
	// Case 3: primitive, low=0, low<high, high<max, max>cap, low<len, high<len - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:2:12]) // invalid: max>cap
}
`}, 1, gosec.NewConfig()},
	// Case 4: primitive, low=0, low<high, high=max, max<cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:3:3]) // valid: high=max
}
`}, 0, gosec.NewConfig()},
	// Case 5: primitive, low=0, low<high, high=max, max=cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:4:4]) // valid: high=max, within bounds
}
`}, 0, gosec.NewConfig()},
	// Case 6: primitive, low=0, low<high, high<len, max>cap, low<len - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:4:12]) // invalid: max>cap
}
`}, 1, gosec.NewConfig()},
	// Case 7: primitive, low=0, low=high, high<max, max<cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:0:5]) // valid: empty slice, low=high
}
`}, 0, gosec.NewConfig()},
	// Case 8: primitive, low=0, low=high, high=max, max<cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[0:0:0]) // valid: all indices 0
}
`}, 0, gosec.NewConfig()},
	// Case 9: primitive, low>0, low<high, high<max, max<cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[1:3:7]) // valid: standard case
}
`}, 0, gosec.NewConfig()},
	// Case 10: primitive, low>0, low<high, high=max, max=cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[2:4:4]) // valid: high=max
}
`}, 0, gosec.NewConfig()},
	// Case 11: primitive, low>0, low=high, high<max, max<cap, low<len, high=len - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[4:4:8]) // valid: empty slice at index 4
}
`}, 0, gosec.NewConfig()},
	// Case 12: primitive, low>0, low<high, high>len, high<max, max<cap - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[2:8:9]) // invalid: high>len
}
`}, 1, gosec.NewConfig()},
	// Case 13: primitive, low>0, low<high, high<len, high<max, max>cap, low<len - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[1:3:15]) // invalid: max>cap
}
`}, 1, gosec.NewConfig()},
	// Case 14: primitive, low=len, low=high, high<max, max<cap - VALID (empty slice at end)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[6:6:8]) // valid: empty slice at end
}
`}, 0, gosec.NewConfig()},
	// Case 15: primitive, low>len, low<high, high>len, high<max, max<cap - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[8:9:10]) // invalid: low>len, high>len
}
`}, 1, gosec.NewConfig()},
	// Case 16: primitive, low>len, low<high, high>len, high<max, max<cap - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[7:8:9]) // invalid: low>len, high>len
}
`}, 1, gosec.NewConfig()},
	// Case 17: primitive, low<high, high=len, high<max, max<cap - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6, 10)
	fmt.Println(s[2:6:8]) // valid: high=len
}
`}, 0, gosec.NewConfig()},
	// Case 18: named type, low=0, low<high, high<max, max<cap, low<len, high<len - VALID
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 6, 10)
	fmt.Println(s[0:3:7]) // valid: named type
}
`}, 0, gosec.NewConfig()},
	// Case 19: named type, low>0, low<high, high<max, max>cap, low<len, high<len - INVALID
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 6, 10)
	fmt.Println(s[1:4:15]) // invalid: max>cap on named type
}
`}, 1, gosec.NewConfig()},
	// Case 20: zero-length slice, low=0, low=high, high<max, max<cap - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0, 10)
	fmt.Println(s[0:0:5]) // valid: empty slice operations
}
`}, 0, gosec.NewConfig()},
	// Case 21: zero-length slice, low>0, low<high, high<max, max<cap - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0, 10)
	fmt.Println(s[1:2:5]) // invalid: low>len on zero-length slice
}
`}, 1, gosec.NewConfig()},
	// Case 22: len=cap, low<high, high<max, max>cap - INVALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[1:4:10]) // invalid: max>cap when len=cap
}
`}, 1, gosec.NewConfig()},
	// Case 23: len=cap, low<high, high=len, high<max, max=cap - VALID
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[2:8:8]) // valid: high=len=cap, max=cap
}
`}, 0, gosec.NewConfig()},
	// 1-index slice operations - valid start-only slice within bounds
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[5:]) // valid: start=5 < length=8
}
`}, 0, gosec.NewConfig()},
	// 1-index slice operations - invalid start-only slice out of bounds
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[10:]) // invalid: start=10 > length=8
}
`}, 1, gosec.NewConfig()},
	// 1-index slice operations - valid end-only slice within bounds
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[:6]) // valid: end=6 <= length=8
}
`}, 0, gosec.NewConfig()},
	// 1-index slice operations - invalid end-only slice out of bounds
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[:12]) // invalid: end=12 > length=8
}
`}, 1, gosec.NewConfig()},
	// 1-index slice operations - edge case at boundary
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[8:]) // valid: start=8 == length=8 (empty slice)
}
`}, 0, gosec.NewConfig()},
	// 1-index slice operations - edge case at boundary for end
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[:8]) // valid: end=8 == length=8
}
`}, 0, gosec.NewConfig()},
	// Same-index slice operations - valid same indices within bounds
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[3:3]) // valid: empty slice at index 3
}
`}, 0, gosec.NewConfig()},
	// Same-index slice operations - invalid same indices out of bounds
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[10:10]) // invalid: both indices=10 > length=8
}
`}, 1, gosec.NewConfig()},
	// Same-index slice operations - valid at boundary
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[8:8]) // valid: empty slice at end
}
`}, 0, gosec.NewConfig()},
	// Same-index slice operations - valid at start
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 8)
	fmt.Println(s[0:0]) // valid: empty slice at start
}
`}, 0, gosec.NewConfig()},

	// 1-index slice operations with zero-length slice - valid
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0, 5)
	fmt.Println(s[0:]) // valid: start=0 == length=0
}
`}, 0, gosec.NewConfig()},
	// 1-index slice operations with zero-length slice - invalid
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0, 5)
	fmt.Println(s[1:]) // invalid: start=1 > length=0
}
`}, 1, gosec.NewConfig()},

	// Function parameter with 3-index slice operations - unguarded
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 5, 10)
	processSlice(s)
}

func processSlice(s []int) {
	fmt.Println(s[1:3:8]) // potentially unsafe without capacity check
}
`}, 1, gosec.NewConfig()},
	// Function parameter with 3-index slice operations - capacity check not recognized
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 5, 10)
	processSlice(s)
}

func processSlice(s []int) {
	if cap(s) >= 8 {
		fmt.Println(s[1:3:8]) // analyzer doesn't recognize capacity bounds for 3-index slices
	}
}
`}, 1, gosec.NewConfig()},
	// Full slice operations [:] - valid on regular slice
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 5)
	fmt.Println(s[:]) // valid: full slice, equivalent to s[0:len(s)]
}
`}, 0, gosec.NewConfig()},
	// Full slice operations [:] - valid on zero-length slice
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 0)
	fmt.Println(s[:]) // valid: full slice of empty slice
}
`}, 0, gosec.NewConfig()},
	// Full slice operations [:] - valid on slice with capacity
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 3, 10)
	fmt.Println(s[:]) // valid: full slice respects length, not capacity
}
`}, 0, gosec.NewConfig()},
	// Full slice operations [:] - flagged on function parameter (conservative)
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 5)
	processSlice(s)
}

func processSlice(s []int) {
	copy := s[:] // analyzer is conservative about function parameters
	fmt.Println(copy)
}
`}, 1, gosec.NewConfig()},
	// Full slice operations [:] - valid on named slice type
	{[]string{`
package main

import "fmt"

type MySlice []int

func main() {
	var s MySlice = make([]int, 4)
	fmt.Println(s[:]) // valid: full slice on named type
}
`}, 0, gosec.NewConfig()},
	// Full slice operations [:] - valid in slice assignment
	{[]string{`
package main

import "fmt"

func main() {
	s := make([]int, 6)
	s[0] = 1
	s[5] = 6
	
	// Create a copy using full slice
	copy := s[:]
	fmt.Println(copy)
}
`}, 0, gosec.NewConfig()},
}
