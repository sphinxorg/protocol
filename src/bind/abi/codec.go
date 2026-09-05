package abi

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sphinxfndorg/protocol/src/contracts"
)

// EncodeCall validates and canonicalizes a native-contract method call.
func EncodeCall(schema Contract, method string, args map[string]string) ([]byte, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	definition, err := schema.Method(method)
	if err != nil {
		return nil, err
	}
	if args == nil {
		args = map[string]string{}
	}
	for _, input := range definition.Inputs {
		if input.Required && strings.TrimSpace(args[input.Name]) == "" {
			return nil, fmt.Errorf("ABI method %s requires %s", method, input.Name)
		}
	}
	return contracts.BuildCallData(&contracts.CallSpec{Method: method, Args: args})
}

// DecodeCall decodes and validates canonical call data against schema.
func DecodeCall(schema Contract, data []byte) (*contracts.CallSpec, error) {
	var call contracts.CallSpec
	if err := json.Unmarshal(data, &call); err != nil {
		return nil, fmt.Errorf("decode ABI call: %w", err)
	}
	if _, err := EncodeCall(schema, call.Method, call.Args); err != nil {
		return nil, err
	}
	call.Method = strings.ToLower(strings.TrimSpace(call.Method))
	return &call, nil
}
