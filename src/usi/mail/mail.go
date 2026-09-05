// Package mail transports already-encrypted USI vaults between peers.
//
// It intentionally does not encrypt, decrypt, or inspect a vault. The vault
// remains the end-to-end encrypted payload; this package only supplies a
// small SMTP-inspired TCP envelope for delivery.
package mail

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ProtocolName    = "USI-MAIL/1"
	DefaultMaxBytes = 512 << 20 // 512 MiB
)

var (
	ErrInvalidAddress = errors.New("mail peer address must be host:port")
	ErrInvalidVault   = errors.New("mail attachment must be a .vault file")
)

// Envelope is public routing metadata. The vault body is opaque and remains
// encrypted for the recipient(s) selected when it was created.
type Envelope struct {
	ID       string    `json:"id"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Filename string    `json:"filename"`
	Size     int64     `json:"size"`
	SHA256   string    `json:"sha256"`
	Created  time.Time `json:"created"`
}

// Server receives USI-MAIL connections and writes each accepted vault into
// MailDir/<recipient fingerprint>/. Set AcceptRecipient to restrict a peer to
// its own identity fingerprint.
type Server struct {
	MailDir         string
	MaxMessageBytes int64
	AcceptRecipient func(fingerprint string) bool
}

func (s *Server) Serve(listener net.Listener) error {
	if s.MailDir == "" {
		return errors.New("mail directory is required")
	}
	if s.MaxMessageBytes <= 0 {
		s.MaxMessageBytes = DefaultMaxBytes
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			_ = s.serveConn(conn)
		}()
	}
}

func (s *Server) ListenAndServe(ctx context.Context, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return s.Serve(listener)
}

func (s *Server) serveConn(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	defer w.Flush()
	writeReply(w, 220, ProtocolName+" ready")

	if line, err := readLine(r); err != nil || !strings.HasPrefix(line, "HELO ") {
		writeReply(w, 500, "expected HELO")
		return errors.New("expected HELO")
	}
	writeReply(w, 250, "hello")
	from, err := readCommandValue(r, "MAIL FROM:")
	if err != nil || from == "" {
		writeReply(w, 501, "invalid MAIL FROM")
		return errors.New("invalid MAIL FROM")
	}
	writeReply(w, 250, "sender accepted")
	to, err := readCommandValue(r, "RCPT TO:")
	if err != nil || to == "" || (s.AcceptRecipient != nil && !s.AcceptRecipient(to)) {
		writeReply(w, 550, "recipient unavailable")
		return errors.New("recipient unavailable")
	}
	writeReply(w, 250, "recipient accepted")
	if line, err := readLine(r); err != nil || line != "DATA" {
		writeReply(w, 503, "expected DATA")
		return errors.New("expected DATA")
	}
	writeReply(w, 354, "send envelope then base64 vault; finish with a single dot")
	envelope, err := readEnvelope(r)
	if err != nil || envelope.From != from || envelope.To != to || envelope.Size < 0 || envelope.Size > s.MaxMessageBytes {
		writeReply(w, 554, "invalid envelope")
		return errors.New("invalid envelope")
	}
	if !strings.HasSuffix(strings.ToLower(envelope.Filename), ".vault") {
		writeReply(w, 554, "attachment must be a .vault file")
		return ErrInvalidVault
	}
	path, err := s.storePayload(envelope, r)
	if err != nil {
		writeReply(w, 554, "delivery rejected")
		return err
	}
	writeReply(w, 250, "queued "+filepath.Base(path))
	return nil
}

// SendVault delivers a .vault file to a peer. Peer endpoints are ordinary
// TCP addresses such as "203.0.113.8:2525"; ports below 1024 are avoided so a
// USI peer can run without elevated privileges.
func SendVault(ctx context.Context, peerAddress, from, to, vaultPath string) (Envelope, error) {
	if _, _, err := net.SplitHostPort(peerAddress); err != nil {
		return Envelope{}, ErrInvalidAddress
	}
	if !strings.HasSuffix(strings.ToLower(vaultPath), ".vault") {
		return Envelope{}, ErrInvalidVault
	}
	file, err := os.Open(vaultPath)
	if err != nil {
		return Envelope{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Envelope{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return Envelope{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Envelope{}, err
	}
	envelope := Envelope{ID: fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(hash.Sum(nil)[:8])), From: from, To: to, Filename: filepath.Base(vaultPath), Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)), Created: time.Now().UTC()}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", peerAddress)
	if err != nil {
		return Envelope{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
	if _, err := expectReply(r, 220); err != nil {
		return Envelope{}, err
	}
	for _, command := range []string{"HELO usi", "MAIL FROM:" + from, "RCPT TO:" + to, "DATA"} {
		if _, err := fmt.Fprintln(w, command); err != nil {
			return Envelope{}, err
		}
		if err := w.Flush(); err != nil {
			return Envelope{}, err
		}
		want := 250
		if command == "DATA" {
			want = 354
		}
		if _, err := expectReply(r, want); err != nil {
			return Envelope{}, err
		}
	}
	header, err := json.Marshal(envelope)
	if err != nil {
		return Envelope{}, err
	}
	if _, err := fmt.Fprintln(w, string(header)); err != nil {
		return Envelope{}, err
	}
	encoder := base64.NewEncoder(base64.StdEncoding, lineWriter{w: w})
	if _, err := io.Copy(encoder, file); err != nil {
		return Envelope{}, err
	}
	if err := encoder.Close(); err != nil {
		return Envelope{}, err
	}
	if _, err := fmt.Fprint(w, "\n.\n"); err != nil {
		return Envelope{}, err
	}
	if err := w.Flush(); err != nil {
		return Envelope{}, err
	}
	if _, err := expectReply(r, 250); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func (s *Server) storePayload(envelope Envelope, r *bufio.Reader) (string, error) {
	dir := filepath.Join(s.MailDir, safePart(envelope.To))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, safePart(envelope.ID)+".vault")
	temp, err := os.CreateTemp(dir, ".incoming-*.vault")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	decoder := base64.NewDecoder(base64.StdEncoding, io.LimitReader(&dataReader{r: r}, encodedLimit(envelope.Size)))
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(decoder, envelope.Size+1))
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil || written != envelope.Size || hex.EncodeToString(hash.Sum(nil)) != envelope.SHA256 {
		return "", errors.New("vault integrity check failed")
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return "", err
	}
	meta, _ := json.MarshalIndent(envelope, "", "  ")
	if err := os.WriteFile(path+".json", meta, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func readEnvelope(r *bufio.Reader) (Envelope, error) {
	line, err := readLine(r)
	if err != nil {
		return Envelope{}, err
	}
	var e Envelope
	return e, json.Unmarshal([]byte(line), &e)
}
func readCommandValue(r *bufio.Reader, prefix string) (string, error) {
	line, err := readLine(r)
	if err != nil || !strings.HasPrefix(line, prefix) {
		return "", errors.New("invalid command")
	}
	return strings.TrimSpace(strings.TrimPrefix(line, prefix)), nil
}
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
func writeReply(w *bufio.Writer, code int, message string) {
	_, _ = fmt.Fprintf(w, "%d %s\r\n", code, message)
	_ = w.Flush()
}
func expectReply(r *bufio.Reader, expected int) (string, error) {
	line, err := readLine(r)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(line, fmt.Sprintf("%d ", expected)) {
		return "", fmt.Errorf("mail peer replied %q", line)
	}
	return line, nil
}
func safePart(value string) string {
	value = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, value)
	if value == "" {
		return "unknown"
	}
	return value
}
func encodedLimit(size int64) int64 { return ((size+2)/3)*4 + 4096 }

type lineWriter struct{ w *bufio.Writer }

func (l lineWriter) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > 76 {
			n = 76
		}
		if _, err := l.w.Write(p[:n]); err != nil {
			return 0, err
		}
		if _, err := l.w.WriteString("\n"); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return written, nil
}

// dataReader ends DATA at a line containing only a dot.
type dataReader struct {
	r       *bufio.Reader
	pending []byte
	done    bool
}

func (d *dataReader) Read(p []byte) (int, error) {
	if len(d.pending) == 0 && !d.done {
		line, err := d.r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		if strings.TrimSpace(line) == "." {
			d.done = true
		} else {
			d.pending = []byte(line)
		}
	}
	if len(d.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}
