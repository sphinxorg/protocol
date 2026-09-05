package abi

import "testing"

func TestWASMFunctionArgumentsRoundTrip(t *testing.T) {
	data, err := EncodeWASMFunctionCall("transfer", 7, 99)
	if err != nil {
		t.Fatal(err)
	}
	args, err := DecodeWASMFunctionCall("transfer", data)
	if err != nil || len(args) != 2 || args[0] != 7 || args[1] != 99 {
		t.Fatalf("args=%v err=%v", args, err)
	}
	if _, err := DecodeWASMFunctionCall("mint", data); err == nil {
		t.Fatal("expected selector mismatch")
	}
}
