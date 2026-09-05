package mail

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSendVaultDeliversOpaqueFile(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "report.vault")
	body := []byte("already encrypted vault bytes")
	if err := os.WriteFile(vaultPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &Server{MailDir: filepath.Join(dir, "inbox"), AcceptRecipient: func(v string) bool { return v == "recipient" }}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	envelope, err := SendVault(ctx, listener.Addr().String(), "sender", "recipient", vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "inbox", "recipient", envelope.ID+".vault"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("received %q, want %q", got, body)
	}
	_ = listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
