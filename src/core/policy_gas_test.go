// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

func TestValidateTransactionPolicyEnforcesPolicyGasQuote(t *testing.T) {
	bc := &Blockchain{}
	tx := &types.Transaction{
		Sender:     "sender",
		Receiver:   "receiver",
		Amount:     big.NewInt(1),
		GasLimit:   big.NewInt(21000),
		GasPrice:   big.NewInt(1000000000),
		ReturnData: []byte("anchor"),
	}

	if err := bc.ValidateTransactionPolicy(tx); err == nil {
		t.Fatal("expected data transaction with transfer-only gas limit to be rejected")
	}

	quote := policy.GetDefaultPolicyParams().QuoteTransactionGas(uint64(len(tx.ReturnData)))
	tx.GasLimit = quote.GasLimit
	tx.GasPrice = quote.GasPrice
	if err := bc.ValidateTransactionPolicy(tx); err != nil {
		t.Fatalf("expected policy gas quote to be accepted: %v", err)
	}
}
