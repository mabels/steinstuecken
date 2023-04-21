package h2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"os/signal"

	"github.com/mabels/steinstuecken/tunnel/config"
	"github.com/posener/h2conn"
	"golang.org/x/net/http2"

	"github.com/rs/zerolog/log"
)

type Tunnel struct {
	Conn   *h2conn.Conn
	Resp   *http.Response
	Ctx    context.Context
	Client h2conn.Client
	Cancel func()
	Config config.SsnConfigClient
}

func NewTunnelClient(ssnc config.SsnConfigClient) (tunnel Tunnel, err error) {
	tunnel.Config = ssnc
	var certs tls.Certificate
	certs, err = tls.LoadX509KeyPair(ssnc.CertFile, ssnc.KeyFile)
	if err != nil {
		log.Error().Err(err).Msg("LoadX509KeyPair")
		return
		// log.Fatalf("LoadKeys:%v", err)
	}
	cp := x509.NewCertPool()
	cb, err := os.ReadFile(ssnc.CertFile)
	if err != nil {
		log.Error().Err(err).Msg("ReadFile")
		return
	}
	cp.AppendCertsFromPEM(cb)
	t := &http2.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{certs},
			RootCAs:      cp,
		},
	}
	var cancel func()
	tunnel.Ctx, tunnel.Cancel = context.WithCancel(context.Background())

	go catchSignal(cancel)

	// We use a client with custom http2.Transport since the server certificate is not signed by
	// an authorized CA, and this is the way to ignore certificate verification errors.
	tunnel.Client = h2conn.Client{
		Client: &http.Client{
			Transport: t,
		},
	}
	return
}

func catchSignal(cancel context.CancelFunc) {
	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Info().Msg("Cancelling due to interrupt")
	cancel()
}
