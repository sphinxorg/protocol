// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SVM1Magic marks code for the deterministic, deliberately small contract VM.
// It has no host time, randomness, networking, floating point, or recursion.
var SVM1Magic = []byte{'S', 'V', 'M', '1'}

const (
	SVMStop  = byte(0x00)
	SVMPush8 = byte(0x01)
	SVMAdd   = byte(0x02)
	SVMSub   = byte(0x03)
	SVMMul   = byte(0x04)
	SVMDiv   = byte(0x05)
	SVMStore = byte(0x10)
	SVMLoad  = byte(0x11)
	// SVMCallDataWord pops a byte offset and pushes an eight-byte big-endian
	// word from transaction call data (zero-padded past its end).
	SVMCallDataWord = byte(0x12)
	SVMReturn       = byte(0xff)
)

// AnalyzeSVM validates an SVM1 program without executing it and returns its
// exact operation count. SVM1 has no branches, so this is deterministic and
// lets mempool admission enforce the same policy gas floor as block execution.
func AnalyzeSVM(code []byte) (uint64, error) {
	if len(code) < len(SVM1Magic) || string(code[:len(SVM1Magic)]) != string(SVM1Magic) {
		return 0, errors.New("invalid SVM1 code")
	}
	var operations uint64
	for pc := len(SVM1Magic); pc < len(code); {
		operations++
		op := code[pc]
		pc++
		switch op {
		case SVMStop, SVMReturn:
			if pc != len(code) {
				return 0, errors.New("SVM1 code after terminal instruction")
			}
			return operations, nil
		case SVMPush8:
			if pc+8 > len(code) {
				return 0, errors.New("svm push out of bounds")
			}
			pc += 8
		case SVMAdd, SVMSub, SVMMul, SVMDiv, SVMStore, SVMLoad, SVMCallDataWord:
			// Valid single-byte operation.
		default:
			return 0, fmt.Errorf("unsupported SVM1 opcode 0x%02x", op)
		}
	}
	return 0, errors.New("svm program terminated without stop")
}

// ExecuteSVM runs SVM1 code. Storage keys and values are uint64, encoded in
// deterministic big-endian form. It returns consumed operation count.
func ExecuteSVM(store Store, address string, code []byte, maxOperations uint64) (*ExecutionResult, uint64, error) {
	return ExecuteSVMWithCallData(store, address, code, nil, maxOperations)
}

// ExecuteSVMWithCallData executes SVM1 with immutable transaction input.
func ExecuteSVMWithCallData(store Store, address string, code, callData []byte, maxOperations uint64) (*ExecutionResult, uint64, error) {
	expectedOperations, err := AnalyzeSVM(code)
	if err != nil {
		return nil, 0, err
	}
	if expectedOperations > maxOperations {
		return nil, expectedOperations, errors.New("svm operation limit exceeded")
	}
	stack := make([]uint64, 0, 64)
	pop := func() (uint64, error) {
		if len(stack) == 0 {
			return 0, errors.New("svm stack underflow")
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v, nil
	}
	var ops uint64
	for pc := len(SVM1Magic); pc < len(code); {
		ops++
		op := code[pc]
		pc++
		switch op {
		case SVMStop, SVMReturn:
			result := uint64(0)
			if len(stack) > 0 {
				result = stack[len(stack)-1]
			}
			return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{"result": fmt.Sprintf("%d", result)}}, ops, nil
		case SVMPush8:
			if pc+8 > len(code) {
				return nil, ops, errors.New("svm push out of bounds")
			}
			stack = append(stack, binary.BigEndian.Uint64(code[pc:pc+8]))
			pc += 8
		case SVMAdd, SVMSub, SVMMul, SVMDiv:
			b, err := pop()
			if err != nil {
				return nil, ops, err
			}
			a, err := pop()
			if err != nil {
				return nil, ops, err
			}
			if op == SVMDiv && b == 0 {
				return nil, ops, errors.New("svm division by zero")
			}
			switch op {
			case SVMAdd:
				stack = append(stack, a+b)
			case SVMSub:
				stack = append(stack, a-b)
			case SVMMul:
				stack = append(stack, a*b)
			case SVMDiv:
				stack = append(stack, a/b)
			}
		case SVMStore:
			value, err := pop()
			if err != nil {
				return nil, ops, err
			}
			key, err := pop()
			if err != nil {
				return nil, ops, err
			}
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, value)
			store.SetContractStorage(address, fmt.Sprintf("svm:%016x", key), buf)
		case SVMLoad:
			key, err := pop()
			if err != nil {
				return nil, ops, err
			}
			value := uint64(0)
			if data, err := store.GetContractStorage(address, fmt.Sprintf("svm:%016x", key)); err == nil && len(data) == 8 {
				value = binary.BigEndian.Uint64(data)
			}
			stack = append(stack, value)
		case SVMCallDataWord:
			offset, err := pop()
			if err != nil {
				return nil, ops, err
			}
			word := make([]byte, 8)
			if offset < uint64(len(callData)) {
				copy(word, callData[offset:])
			}
			stack = append(stack, binary.BigEndian.Uint64(word))
		default:
			return nil, ops, fmt.Errorf("unsupported SVM1 opcode 0x%02x", op)
		}
	}
	return nil, ops, errors.New("svm program terminated without stop")
}
