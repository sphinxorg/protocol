// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// WASMFunctionSelector returns the canonical first calldata word for a WASM
// function. Contracts read it with sphinx.calldata_word(0); subsequent words
// begin at offsets 8, 16, and so on. It is deliberately binary, not JSON.
func WASMFunctionSelector(function string) (uint64, error) {
	function = strings.TrimSpace(function)
	if function == "" {
		return 0, errors.New("WASM function name is required")
	}
	sum := sha256.Sum256([]byte("sphinx-wasm-abi-v1:" + function))
	return binary.BigEndian.Uint64(sum[:8]), nil
}

// EncodeWASMArguments encodes words in the exact big-endian layout consumed
// by sphinx.calldata_word. It is suitable for numeric IDs, amounts, counters,
// booleans (0/1), and selectors.
func EncodeWASMArguments(words ...uint64) []byte {
	data := make([]byte, len(words)*8)
	for i, word := range words {
		binary.BigEndian.PutUint64(data[i*8:], word)
	}
	return data
}

// DecodeWASMArguments validates and decodes word-aligned calldata.
func DecodeWASMArguments(data []byte) ([]uint64, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("WASM calldata must be 8-byte aligned, got %d bytes", len(data))
	}
	words := make([]uint64, len(data)/8)
	for i := range words {
		words[i] = binary.BigEndian.Uint64(data[i*8:])
	}
	return words, nil
}

// EncodeWASMFunctionCall constructs calldata as selector followed by typed
// u64 arguments. The same function name always has the same selector across
// Rust, C/C++, TinyGo, AssemblyScript, and Go SDK users.
func EncodeWASMFunctionCall(function string, args ...uint64) ([]byte, error) {
	selector, err := WASMFunctionSelector(function)
	if err != nil {
		return nil, err
	}
	words := make([]uint64, 1, len(args)+1)
	words[0] = selector
	words = append(words, args...)
	return EncodeWASMArguments(words...), nil
}

// DecodeWASMFunctionCall verifies a selector and returns only its arguments.
func DecodeWASMFunctionCall(function string, data []byte) ([]uint64, error) {
	words, err := DecodeWASMArguments(data)
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, errors.New("WASM calldata is missing function selector")
	}
	selector, err := WASMFunctionSelector(function)
	if err != nil {
		return nil, err
	}
	if words[0] != selector {
		return nil, errors.New("WASM function selector mismatch")
	}
	return words[1:], nil
}
