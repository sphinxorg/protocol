// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// usi-mail-peer runs a mailbox endpoint for encrypted USI vault delivery.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	usimail "github.com/sphinxfndorg/protocol/src/usi/mail"
)

func main() {
	listen := flag.String("listen", ":2525", "TCP address to listen on")
	maildir := flag.String("maildir", "usi-mail", "directory for received vaults")
	recipient := flag.String("recipient", "", "local recipient fingerprint/address to accept (required)")
	flag.Parse()
	if strings.TrimSpace(*recipient) == "" {
		log.Fatal("-recipient is required; it prevents this peer from accepting mail for other identities")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &usimail.Server{
		MailDir: *maildir,
		AcceptRecipient: func(value string) bool {
			return value == strings.TrimSpace(*recipient)
		},
	}
	log.Printf("USI mail peer listening on %s; encrypted vaults will be saved in %s", *listen, *maildir)
	if err := server.ListenAndServe(ctx, *listen); err != nil {
		log.Fatal(err)
	}
}
