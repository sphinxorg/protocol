// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/binary"
	"errors"
	"testing"
)

type memoryStore struct{ values map[string][]byte }

func (s *memoryStore) key(address, kind, key string) string { return address + ":" + kind + ":" + key }
func (s *memoryStore) ContractExists(address string) bool {
	_, ok := s.values[s.key(address, "meta", "")]
	return ok
}
func (s *memoryStore) SetContractCode(address string, code []byte) {
	s.values[s.key(address, "code", "")] = code
}
func (s *memoryStore) GetContractCode(address string) ([]byte, error) {
	v, ok := s.values[s.key(address, "code", "")]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}
func (s *memoryStore) SetContractMeta(address string, meta []byte) {
	s.values[s.key(address, "meta", "")] = meta
}
func (s *memoryStore) GetContractMeta(address string) ([]byte, error) {
	v, ok := s.values[s.key(address, "meta", "")]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}
func (s *memoryStore) SetContractStorage(address, key string, value []byte) {
	s.values[s.key(address, "storage", key)] = value
}
func (s *memoryStore) GetContractStorage(address, key string) ([]byte, error) {
	v, ok := s.values[s.key(address, "storage", key)]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}

func push(value uint64) []byte {
	b := make([]byte, 9)
	b[0] = SVMPush8
	binary.BigEndian.PutUint64(b[1:], value)
	return b
}

func TestExecuteSVMStoresAndLoadsValue(t *testing.T) {
	store := &memoryStore{values: map[string][]byte{}}
	code := append([]byte{}, SVM1Magic...)
	code = append(code, push(7)...)
	code = append(code, push(42)...)
	code = append(code, SVMStore)
	code = append(code, push(7)...)
	code = append(code, SVMLoad, SVMReturn)

	result, operations, err := ExecuteSVM(store, "contract", code, 100)
	if err != nil {
		t.Fatal(err)
	}
	if operations == 0 || result.Return["result"] != "42" {
		t.Fatalf("unexpected result: %#v, ops=%d", result, operations)
	}
}

func TestAnalyzeSVMRejectsTrailingCode(t *testing.T) {
	code := append([]byte{}, SVM1Magic...)
	code = append(code, SVMStop, SVMStop)
	if _, err := AnalyzeSVM(code); err == nil {
		t.Fatal("expected trailing code after stop to be rejected")
	}
}

func TestExecuteSVMReadsCallData(t *testing.T) {
	store := &memoryStore{values: map[string][]byte{}}
	code := append([]byte{}, SVM1Magic...)
	code = append(code, push(0)...)
	code = append(code, SVMCallDataWord, SVMReturn)
	input := make([]byte, 8)
	binary.BigEndian.PutUint64(input, 99)
	result, _, err := ExecuteSVMWithCallData(store, "contract", code, input, 100)
	if err != nil || result.Return["result"] != "99" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
