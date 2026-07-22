// Package vulnlib simulates a vulnerable dependency. The app calls
// ProcessQuery which would contain the vulnerable code path in a real CVE
// scenario.
package vulnlib

import "fmt"

// ProcessQuery simulates a function that processes user input in an
// unsafe manner. In a real CVE scenario this would be the vulnerable
// symbol that a security analyst needs to prove is reached.
func ProcessQuery(input string) string {
	return fmt.Sprintf("processed: %s", input)
}

// UnusedFunction is exported but never called by the app. golem should
// still discover it as part of the dependency's API surface.
func UnusedFunction() string {
	return "unused"
}
