package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, `Error: Cannot find module '/app/pkg/config'`)
	fmt.Fprintln(os.Stderr, `    at Object.<anonymous> (/app/main.go:1:1)`)
	fmt.Fprintln(os.Stderr, `    at Module._compile (node:internal/modules/cjs/loader:1364:14)`)
	fmt.Fprintln(os.Stderr, ``)
	fmt.Fprintln(os.Stderr, `Go runtime v1.25`)
	fmt.Fprintf(os.Stderr, "{ code: 'ERR_MODULE_NOT_FOUND' }\n")
	os.Exit(1)
}
