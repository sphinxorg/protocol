package core

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/contracts"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

func contractGas(bc *Blockchain, deploy bool, code, callData []byte) *big.Int {
	base := bc.ActivePolicy().QuoteTransactionGas(0).GasLimit
	return base.Add(base, bc.ActivePolicy().QuoteContractGas(deploy, uint64(len(code)), uint64(len(callData)), 0).GasLimit)
}

func TestNativeSIP20ContractExecutionUsesStateDB(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := NewStateDB(db)
	bc := &Blockchain{}

	code, err := contracts.BuildDeployCode(&contracts.DeploySpec{Standard: contracts.StandardSIP20, Name: "Token", Symbol: "TOK", InitialSupply: "100"})
	if err != nil {
		t.Fatal(err)
	}
	deploy := &types.Transaction{Sender: "owner", Amount: big.NewInt(0), Nonce: 1, Timestamp: 100, Code: code, GasLimit: contractGas(bc, true, code, nil), GasPrice: big.NewInt(1000000000)}
	if err := bc.ValidateTransactionPolicy(deploy); err != nil {
		t.Fatalf("policy rejected correctly priced deploy: %v", err)
	}
	if err := bc.executeContractTransaction(deploy, state); err != nil {
		t.Fatal(err)
	}
	address := contracts.ContractAddress(deploy.Sender, deploy.Nonce, deploy.Code)

	callData, err := contracts.BuildCallData(&contracts.CallSpec{Method: "transfer", Args: map[string]string{"to": "alice", "amount": "25"}})
	if err != nil {
		t.Fatal(err)
	}
	call := &types.Transaction{Sender: "owner", Amount: big.NewInt(0), ToContract: address, CallData: callData, GasLimit: contractGas(bc, false, nil, callData), GasPrice: big.NewInt(1000000000)}
	if err := bc.executeContractTransaction(call, state); err != nil {
		t.Fatal(err)
	}

	value, err := state.GetContractValue(contractKey(address, "storage", "sip20:balance:alice"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "25" {
		t.Fatalf("alice balance: want 25, got %s", value)
	}
	if _, err := state.Commit(); err != nil {
		t.Fatalf("commit contract state: %v", err)
	}
	reloaded := NewStateDB(db)
	value, err = reloaded.GetContractValue(contractKey(address, "storage", "sip20:balance:alice"))
	if err != nil || string(value) != "25" {
		t.Fatalf("persisted alice balance: %q, err=%v", value, err)
	}
}

func TestSVMDeployGasIncludesDeterministicOperationCount(t *testing.T) {
	bc := &Blockchain{}
	code := append([]byte{}, contracts.SVM1Magic...)
	code = append(code, contracts.SVMStop)
	tx := &types.Transaction{Code: code}
	quote, err := bc.RequiredTransactionGas(tx)
	if err != nil {
		t.Fatal(err)
	}
	base := bc.ActivePolicy().QuoteTransactionGas(0).GasLimit
	contractQuote := bc.ActivePolicy().QuoteContractGas(true, uint64(len(code)), 0, 1).GasLimit
	want := new(big.Int).Add(base, contractQuote)
	if quote.GasLimit.Cmp(want) != 0 {
		t.Fatalf("gas limit: want %s, got %s", want, quote.GasLimit)
	}
}
