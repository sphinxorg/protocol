// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"errors"
	"math/big"
	"time"

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

type TxOptions struct {
	ChainID uint64
	Sender  string
	Nonce   uint64
	// Timestamp is consensus data; zero uses the current time for client-side
	// construction only. Nodes never read local time during execution.
	Timestamp int64
}

func transactionQuote(deploy bool, code, callData []byte) (*big.Int, *big.Int) {
	p := policy.GetDefaultPolicyParams()
	base := p.QuoteTransactionGas(0)
	contract := p.QuoteContractGas(deploy, uint64(len(code)), uint64(len(callData)), 0)
	return new(big.Int).Add(base.GasLimit, contract.GasLimit), new(big.Int).Set(base.GasPrice)
}

func timestamp(options TxOptions) int64 {
	if options.Timestamp != 0 {
		return options.Timestamp
	}
	return time.Now().Unix()
}

// NewSIP20DeployTx constructs an unsigned, policy-quoted token deployment.
// Callers sign it with their normal wallet/signing flow before broadcasting.
func NewSIP20DeployTx(options TxOptions, spec contracts.DeploySpec) (*types.Transaction, error) {
	if options.Sender == "" {
		return nil, errors.New("sender is required")
	}
	spec.Runtime, spec.Standard = contracts.RuntimeNative, contracts.StandardSIP20
	code, err := contracts.BuildDeployCode(&spec)
	if err != nil {
		return nil, err
	}
	gasLimit, gasPrice := transactionQuote(true, code, nil)
	return &types.Transaction{ChainID: options.ChainID, Sender: options.Sender, Amount: big.NewInt(0), Nonce: options.Nonce, Timestamp: timestamp(options), Code: code, GasLimit: gasLimit, GasPrice: gasPrice}, nil
}

// NewSIP20CallTx constructs an unsigned, policy-quoted SIP-20 call.
func NewSIP20CallTx(options TxOptions, contractAddress, method string, args map[string]string) (*types.Transaction, error) {
	if options.Sender == "" || contractAddress == "" {
		return nil, errors.New("sender and contract address are required")
	}
	callData, err := EncodeCall(SIP20ABI, method, args)
	if err != nil {
		return nil, err
	}
	gasLimit, gasPrice := transactionQuote(false, nil, callData)
	return &types.Transaction{ChainID: options.ChainID, Sender: options.Sender, Amount: big.NewInt(0), Nonce: options.Nonce, Timestamp: timestamp(options), ToContract: contractAddress, CallData: callData, GasLimit: gasLimit, GasPrice: gasPrice}, nil
}
