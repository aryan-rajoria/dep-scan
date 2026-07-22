// reachable-app imports and calls the vulnerable dependency's
// ProcessQuery function on a user-controlled path, simulating a real
// CVE reachability scenario.
package main

import (
	"fmt"
	"net/http"

	"github.com/example/vuln-lib"
)

func main() {
	http.HandleFunc("/process", handleProcess)
	fmt.Println("listening on :8080")
	_ = http.ListenAndServe(":8080", nil)
}

func handleProcess(w http.ResponseWriter, r *http.Request) {
	// User-controlled input flows into the vulnerable dependency
	input := r.URL.Query().Get("data")
	result := vulnlib.ProcessQuery(input)
	_, _ = fmt.Fprintf(w, "%s", result)
}
