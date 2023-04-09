package endpoint

import (
	"net"

	"github.com/rs/zerolog/log"
)

type ListenParam struct {
	Name     string // name used for upstream connect
	Addr     string
	Type     string
	ConnQLen int
}

type Bound struct {
	ListenParam ListenParam
	Listen      net.Listener
	Connections chan Conn
}

type Conn struct {
	Bound *Bound
	Conn  net.Conn
}

func NewListen(lp ListenParam) (bound Bound, err error) {
	var listen net.Listener
	listen, err = net.Listen(lp.Type, lp.Addr)
	if err != nil {
		log.Error().Err(err).Msg("NewListen")
		return
	}
	log.Info().Str("Type", lp.Type).Str("Addr", lp.Addr).Msg("NewListen")
	return Bound{
		ListenParam: lp,
		Listen:      listen,
		Connections: make(chan Conn, lp.ConnQLen),
	}, nil
}

func (b *Bound) AcceptLoop() {
	for {
		conn, err := b.Listen.Accept()
		if err != nil {
			log.Error().Str("Addr", b.Listen.Addr().String()).Err(err)
			continue
		}
		log.Info().
			Str("Addr", b.Listen.Addr().String()).
			Str("Remote", conn.RemoteAddr().String()).Msg("Accepted")
		b.Connections <- Conn{
			Bound: b,
			Conn:  conn,
		}
	}
}

func BindEndpoint(epc ListenParam) (bound Bound, err error) {
	bound, err = NewListen(epc)
	if err != nil {
		return
	}
	// go func() {
	// 	opened := true
	// 	for opened {
	// 		var conn endpoint.Conn
	// 		conn, opened = <-ep.Connections
	// 		conn.Conn.Write([]byte("Hello World"))
	// 		conn.Conn.Close()
	// 	}
	// }()
	go func() {
		bound.AcceptLoop()
	}()
	return
}
