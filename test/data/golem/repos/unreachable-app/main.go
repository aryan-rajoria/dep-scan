// unreachable-app declares vuln-lib as a dependency but never calls
// ProcessQuery. The vulnerability must NOT be marked as reachable.
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/health", handleHealth)
	fmt.Println("listening on :8080")
	_ = http.ListenAndServe(":8080", nil)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintf(w, "ok")
}
