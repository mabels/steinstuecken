package h2

import (
	"net"
	"net/http"

	"github.com/mabels/steinstuecken/tunnel/config"
	"github.com/posener/h2conn"

	"github.com/rs/zerolog/log"
)

type H2ConnSrv interface {
	Listen(lnr net.Listener)
	Handler(w http.ResponseWriter, r *http.Request, conn *h2conn.Conn)
}

type handler struct {
	h2ConnSrv H2ConnSrv
}

func Serve(ssnConfig config.SsnConfigServer, h2srv H2ConnSrv) error {
	srv := &http.Server{Addr: ssnConfig.Addr, Handler: handler{
		h2ConnSrv: h2srv,
	}}
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if h2srv != nil {
		h2srv.Listen(ln)
	}
	// defer ln.Close()
	return srv.ServeTLS(ln, ssnConfig.CertFile, ssnConfig.KeyFile)
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := h2conn.Accept(w, r)
	if err != nil {
		log.Error().Str("remoteAddr", r.RemoteAddr).Err(err).Msg("Failed creating connection")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	h.h2ConnSrv.Handler(w, r, conn)
}
