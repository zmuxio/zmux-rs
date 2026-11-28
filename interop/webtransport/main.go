// Loopback peer for the native Go and Rust WebTransport adapters.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/zmuxio/zmux-go/zmuxh3"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	switch {
	case len(args) == 1 && args[0] == "server":
		return serve(ctx)
	case len(args) == 3 && args[0] == "client":
		id, err := strconv.Atoi(args[2])
		if err != nil || (id != 0 && id != 4) {
			return fmt.Errorf("invalid requested CONNECT ID %q", args[2])
		}
		return dial(ctx, args[1], id != 0)
	default:
		return fmt.Errorf("usage: go-peer server | client URL CONNECT-ID")
	}
}

func dial(ctx context.Context, url string, reserve bool) error {
	// Only the loopback test client accepts the Rust fixture's ephemeral certificate.
	transport := &zmuxh3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.Close()
	var connection *quic.Conn
	transport.DialAddr = func(ctx context.Context, addr string, tls *tls.Config, config *quic.Config) (*quic.Conn, error) {
		conn, err := quic.DialAddr(ctx, addr, tls, config)
		if err != nil {
			return nil, err
		}
		if reserve {
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				_ = conn.CloseWithError(0, "")
				return nil, err
			}
			if stream.StreamID() != 0 {
				_ = conn.CloseWithError(0, "")
				return nil, fmt.Errorf("reserved stream ID %d, want 0", stream.StreamID())
			}
		}
		connection = conn
		return conn, nil
	}
	session, err := zmuxh3.DialSession(ctx, transport, url, nil, nil)
	if err != nil {
		return fmt.Errorf("Go CONNECT: %w", err)
	}
	if err := exchange(ctx, session, true); err != nil {
		return err
	}
	if err := session.CloseWithError(42, "done"); err != nil {
		return err
	}
	// Let the owned adapter finish CONNECT before closing the transport.
	select {
	case <-connection.Context().Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func serve(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer packet.Close()
	server := &zmuxh3.Server{H3: &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
	}}
	defer server.Close()
	result := make(chan error, 2)
	server.H3.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := server.Upgrade(w, r)
		if err == nil {
			err = exchange(ctx, session, false)
		}
		if err == nil {
			select {
			case <-session.Context().Done():
				cause := context.Cause(session.Context())
				var closeErr *zmuxh3.SessionError
				if !errors.As(cause, &closeErr) || closeErr.ErrorCode != 42 || closeErr.Message != "done" || !closeErr.Remote {
					err = fmt.Errorf("remote close: %w", cause)
				}
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		result <- err
	})
	fmt.Printf("https://%s/zmux\n%x\n", packet.LocalAddr(), der)
	go func() { result <- server.Serve(packet) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func exchange(ctx context.Context, session *zmuxh3.Session, client bool) error {
	for _, fromClient := range []bool{true, false} {
		prefix := "server"
		if fromClient {
			prefix = "client"
		}
		open := client == fromClient
		if err := exchangePipe(ctx, session, open, prefix+"-pipe"); err != nil {
			return err
		}
		if open {
			lane, err := session.OpenUniStreamSync(ctx)
			if err != nil {
				return err
			}
			if err := writeFIN(ctx, lane, prefix+"-lane"); err != nil {
				return err
			}
			if err := session.SendDatagram([]byte(prefix + "-datagram")); err != nil {
				return err
			}
		} else {
			lane, err := session.AcceptUniStream(ctx)
			if err != nil {
				return err
			}
			if err := readFIN(ctx, lane, prefix+"-lane"); err != nil {
				return err
			}
			payload, err := session.ReceiveDatagram(ctx)
			if err != nil || string(payload) != prefix+"-datagram" {
				return fmt.Errorf("native datagram: %q, %v", payload, err)
			}
		}
	}
	return nil
}

func exchangePipe(ctx context.Context, session *zmuxh3.Session, open bool, payload string) error {
	if open {
		pipe, err := session.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		if err := writeFIN(ctx, pipe, payload); err != nil {
			return err
		}
		return readFIN(ctx, pipe, payload)
	}
	pipe, err := session.AcceptStream(ctx)
	if err != nil {
		return err
	}
	if err := readFIN(ctx, pipe, payload); err != nil {
		return err
	}
	return writeFIN(ctx, pipe, payload)
}

func writeFIN(ctx context.Context, stream *zmuxh3.Stream, text string) error {
	deadline, _ := ctx.Deadline()
	if err := stream.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(stream, text); err != nil {
		return err
	}
	return stream.Close()
}

func readFIN(ctx context.Context, stream *zmuxh3.Stream, text string) error {
	deadline, _ := ctx.Deadline()
	if err := stream.SetReadDeadline(deadline); err != nil {
		return err
	}
	buf, err := io.ReadAll(io.LimitReader(stream, int64(len(text)+1)))
	if err != nil || string(buf) != text {
		return fmt.Errorf("stream %q, want %q: %v", buf, text, err)
	}
	return nil
}
