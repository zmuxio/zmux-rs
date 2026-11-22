// A loopback peer for the Rust WebTransport negotiation test.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/zmuxio/zmux-go"
	"github.com/zmuxio/zmux-go/zmuxh3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Both peers are local test processes with ephemeral certificates.
	if len(os.Args) == 2 {
		tr := &webtransport.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		s, err := zmuxh3.DialSession(ctx, tr, os.Args[1], nil, nil)
		if err != nil {
			return fmt.Errorf("Go dial: %w", err)
		}
		defer s.CloseWithError(0, "")
		st, err := s.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		if err := st.SetDeadline(deadline); err != nil {
			return err
		}
		if _, err := st.Write([]byte("ping")); err != nil {
			return err
		}
		if err := st.Close(); err != nil {
			return err
		}
		reply, err := io.ReadAll(st)
		if err != nil {
			return err
		}
		if string(reply) != "ping" {
			return fmt.Errorf("echo: %q", reply)
		}
		return nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer pc.Close()
	h3 := &http3.Server{
		TLSConfig:  http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}),
		QUICConfig: &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
	}
	webtransport.ConfigureHTTP3Server(h3)
	server := &webtransport.Server{H3: h3}
	defer server.Close()
	listener, err := zmux.NewListener(&zmux.ListenerConfig{
		Config: &zmux.Config{},
		Admission: &zmux.Admission{Peek: 1, Decide: func(_ context.Context, info zmux.CarrierInfo, _ []byte) zmux.Decision {
			if info.Stage == zmux.StageHead {
				return zmux.Decision{Verdict: zmux.VerdictDefer}
			}
			return zmux.Decision{Verdict: zmux.VerdictFallback}
		}},
		Fallback: func(_ context.Context, takeover *zmux.Takeover) {
			pipe := takeover.Pipe()
			session := pipe.W.(zmux.CarrierConner).CarrierConn().(*webtransport.Session)
			if _, err := io.Copy(pipe.W, pipe.R); err != nil {
				fmt.Fprintln(os.Stderr, "Go echo:", err)
				return
			}
			if err := pipe.W.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "Go echo FIN:", err)
				return
			}
			select {
			case <-session.Context().Done():
			case <-ctx.Done():
			}
		},
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	h3.Handler, err = zmuxh3.NewHandler(listener, nil, server)
	if err != nil {
		return err
	}
	fmt.Printf("https://%s/zmux\n", pc.LocalAddr())
	go func() { _ = server.Serve(pc) }()
	<-ctx.Done()
	return nil
}
