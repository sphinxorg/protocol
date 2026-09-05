package bind

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// LoadContractBinary loads compiler output without converting it through text.
// Use this for .wasm and .svm artifacts emitted by Rust, C/C++, TinyGo, or
// another contract compiler.
func LoadContractBinary(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("contract binary path is required")
	}
	code, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read contract binary: %w", err)
	}
	if len(code) == 0 {
		return nil, fmt.Errorf("contract binary is empty")
	}
	return code, nil
}

// BuildWASMDeploymentTx builds an unsigned deploy transaction from raw binary.
func BuildWASMDeploymentTx(options abi.TxOptions, code []byte) (*types.Transaction, error) {
	return abi.NewWASMDeployTx(options, code)
}

// BuildWASMDeploymentTxFromFile loads a compiler artifact and builds its
// unsigned deployment transaction.
func BuildWASMDeploymentTxFromFile(options abi.TxOptions, path string) (*types.Transaction, error) {
	code, err := LoadContractBinary(path)
	if err != nil {
		return nil, err
	}
	return BuildWASMDeploymentTx(options, code)
}

// BuildWASMCallTx creates an unsigned call with raw binary call data.
func BuildWASMCallTx(options abi.TxOptions, contractAddress string, callData []byte) (*types.Transaction, error) {
	return abi.NewWASMCallTx(options, contractAddress, callData)
}

// BuildWASMFunctionCallTx builds a call using the canonical selector-plus-u64
// argument ABI rather than requiring clients to assemble raw call data.
func BuildWASMFunctionCallTx(options abi.TxOptions, contractAddress, function string, args ...uint64) (*types.Transaction, error) {
	return abi.NewWASMFunctionCallTx(options, contractAddress, function, args...)
}

// BuildSVMDeploymentTx builds an unsigned deployment from raw SVM1 bytes.
// SVM artifacts use the same binary-safe path as WASM artifacts.
func BuildSVMDeploymentTx(options abi.TxOptions, code []byte) (*types.Transaction, error) {
	artifact, err := abi.NewBinaryArtifact("svm1", code)
	if err != nil {
		return nil, err
	}
	decoded, err := abi.DecodeArtifactCode(artifact)
	if err != nil {
		return nil, err
	}
	return abi.NewSVMDeployTx(options, decoded)
}

// EncodeRawTransaction produces the canonical hex(JSON(transaction)) wire
// payload accepted by the node's sendrawtransaction RPC method. Code and call
// data remain binary fields and use Go JSON's byte-slice encoding internally.
func EncodeRawTransaction(tx *types.Transaction) (string, error) {
	if tx == nil {
		return "", fmt.Errorf("nil transaction")
	}
	data, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("marshal raw transaction: %w", err)
	}
	return hex.EncodeToString(data), nil
}
