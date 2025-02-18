package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/second-state/WasmEdge-go/wasmedge"
)

func main() {
	log.Println("Warmor Enforcer: Initializing WASM Runtime...")

	// Create a VM instance
	vm := wasmedge.NewVM()
	defer vm.Release()

	// Load and validate WASM file
	wasmFile := filepath.Join("enforcer", "policy_enforcer.wasm")
	if _, err := os.Stat(wasmFile); os.IsNotExist(err) {
		log.Fatalf("WASM policy file not found: %s", wasmFile)
	}

	// Load WASM module
	err := vm.LoadWasmFile(wasmFile)
	if err != nil {
		log.Fatalf("Failed to load WASM file: %v", err)
	}

	// Validate the module
	err = vm.Validate()
	if err != nil {
		log.Fatalf("Failed to validate WASM module: %v", err)
	}

	// Instantiate the module
	err = vm.Instantiate()
	if err != nil {
		log.Fatalf("Failed to instantiate WASM module: %v", err)
	}

	// Run the WASM function `enforce` (assuming it takes no input and returns an i32)
	res, err := vm.Execute("enforce", int32(1234), int32(1000))
	if err != nil {
		log.Fatalf("Failed to execute WASM function: %v", err)
	}

	// Interpret the policy decision
    decision := res[0].(int32)
    fmt.Printf("Policy Decision: %v\n", decision)

    // Handle the policy decision
    if decision == 1 {
        fmt.Println("Action allowed.")
        // Proceed with the action
    } else {
        fmt.Println("Action denied.")
        // Take appropriate measures
    }
}
