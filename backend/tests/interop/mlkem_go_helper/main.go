// Command mlkem-go-helper exposes the Go standard library ML-KEM-768
// implementation (crypto/mlkem) to the cross-implementation interop test in
// the parent directory. Arguments and results are hex; each result is one JSON
// object on standard output.
//
//	mlkem-go-helper keygen                       {"encapsulationKey": ..., "seed": ...}
//	mlkem-go-helper encaps <encapsulation key>   {"ciphertext": ..., "sharedKey": ...}
//	mlkem-go-helper decaps <seed> <ciphertext>   {"sharedKey": ...}
//
// The seed is the 64-byte "d || z" form of the decapsulation key (FIPS 203).
package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const usage = "usage: mlkem-go-helper keygen | encaps <encapsulation key hex> | decaps <seed hex> <ciphertext hex>"

func main() {
	result, err := run(os.Args[1:])
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mlkem-go-helper:", err)
		os.Exit(1)
	}
}

func run(args []string) (map[string]string, error) {
	if len(args) == 0 {
		return nil, errors.New(usage)
	}
	switch command, operands := args[0], args[1:]; command {
	case "keygen":
		if len(operands) != 0 {
			return nil, errors.New(usage)
		}
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, err
		}
		return map[string]string{
			"encapsulationKey": hex.EncodeToString(dk.EncapsulationKey().Bytes()),
			"seed":             hex.EncodeToString(dk.Bytes()),
		}, nil
	case "encaps":
		decoded, err := decodeHex(operands, 1)
		if err != nil {
			return nil, err
		}
		ek, err := mlkem.NewEncapsulationKey768(decoded[0])
		if err != nil {
			return nil, err
		}
		sharedKey, ciphertext := ek.Encapsulate()
		return map[string]string{
			"ciphertext": hex.EncodeToString(ciphertext),
			"sharedKey":  hex.EncodeToString(sharedKey),
		}, nil
	case "decaps":
		decoded, err := decodeHex(operands, 2)
		if err != nil {
			return nil, err
		}
		dk, err := mlkem.NewDecapsulationKey768(decoded[0])
		if err != nil {
			return nil, err
		}
		sharedKey, err := dk.Decapsulate(decoded[1])
		if err != nil {
			return nil, err
		}
		return map[string]string{"sharedKey": hex.EncodeToString(sharedKey)}, nil
	default:
		return nil, errors.New(usage)
	}
}

func decodeHex(operands []string, want int) ([][]byte, error) {
	if len(operands) != want {
		return nil, errors.New(usage)
	}
	decoded := make([][]byte, want)
	for i, operand := range operands {
		b, err := hex.DecodeString(operand)
		if err != nil {
			return nil, fmt.Errorf("operand %d: %w", i+1, err)
		}
		decoded[i] = b
	}
	return decoded, nil
}
