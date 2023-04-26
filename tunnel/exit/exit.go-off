package exit

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/posener/h2conn"
	"github.com/rs/zerolog/log"

	"github.com/mabels/steinstuecken/tunnel/copy_handler"
)

type ExitId string

type Exit interface {
	Id() ExitId
	BufferSize() int
	Resolve() (string, error)
}

type SimpleDnsExit struct {
	Name string
	Port string
}

func (e *SimpleDnsExit) Id() ExitId {
	return ExitId(e.Name)
}

func (e *SimpleDnsExit) BufferSize() int {
	return 4096
}

func (e *SimpleDnsExit) Resolve() (string, error) {
	ip, err := net.LookupIP(e.Name)
	if err != nil {
		return "", err
	}
	addr := ip[0].String()
	if ip[0].To4() == nil {
		addr = fmt.Sprintf("[%s]", ip[0].String())
	}
	return fmt.Sprintf("%s:%s", addr, e.Port), nil
}

type ConnectParam struct {
	ExitId   string
	ConnId   string
	Response http.ResponseWriter
	Request  *http.Request
	Conn     *h2conn.Conn
	Times    struct {
		Connect time.Time
		Resolve time.Time
		NetDial time.Time
		InCopy  time.Time
		OutCopy time.Time
		Total   time.Time
	}
}

func connect(e Exit, cp ConnectParam) {
	cp.Times.Connect = time.Now()
	addr, err := e.Resolve()
	if err != nil {
		log.Error().Str("Component", "exit").Str("ExitId", cp.ExitId).Str("ConnId", cp.ConnId).Err(err).Msg("Resolve")
		return
	}
	cp.Times.Resolve = time.Now()
	log.Info().Str("Component", "exit").Str("ExitId", cp.ExitId).
		Str("ConnId", cp.ConnId).Str("addr", addr).
		TimeDiff("Time", cp.Times.Connect, cp.Times.Resolve).
		Msg("Resolve")

	exitConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Error().Str("Component", "exit").Str("ExitId", cp.ExitId).Str("ConnId", cp.ConnId).Str("addr", addr).Err(err).Msg("net.Dial")
		return
	}
	cp.Times.NetDial = time.Now()
	log.Info().Str("Component", "exit").Str("ExitId", cp.ExitId).
		Str("ConnId", cp.ConnId).Str("addr", addr).
		TimeDiff("Time", cp.Times.Resolve, cp.Times.NetDial).
		Msg("NetDial")
	wg := sync.WaitGroup{}
	var upStreamWritten, downStreamWritten int64
	wg.Add(1)
	go func() {
		ch := copy_handler.CopyHandler{
			ExitId: cp.ExitId,
			ConnId: cp.ConnId,
			Addr:   addr,
			Buf:    make([]byte, e.BufferSize()),
		}
		upStreamWritten, err = ch.Copy(cp.Conn, exitConn)
		cp.Times.InCopy = time.Now()
		log.Info().Str("Component", "exit").Int64("upStreamWritten", downStreamWritten).
			Str("ExitId", cp.ExitId).Str("ConnId", cp.ConnId).Str("addr", addr).
			TimeDiff("Time", cp.Times.NetDial, cp.Times.InCopy).
			Msg("UpStream Copy Done")
		cp.Conn.Close()
		exitConn.Close()
		wg.Add(-1)
	}()
	wg.Add(1)
	go func() {
		ch := copy_handler.CopyHandler{
			ExitId: cp.ExitId,
			ConnId: cp.ConnId,
			Addr:   addr,
			Buf:    make([]byte, e.BufferSize()),
		}
		downStreamWritten, err = ch.Copy(exitConn, cp.Conn)
		cp.Times.OutCopy = time.Now()
		log.Info().Str("Component", "exit").Int64("downStreamWritten", downStreamWritten).
			Str("ExitId", cp.ExitId).Str("ConnId", cp.ConnId).Str("addr", addr).
			TimeDiff("Time", cp.Times.NetDial, cp.Times.OutCopy).
			Msg("DownStream Copy Done")
		cp.Conn.Close()
		exitConn.Close()
		wg.Add(-1)
	}()
	wg.Wait()
	cp.Times.Total = time.Now()
	log.Info().Str("Component", "exit").Int64("totalWritten", upStreamWritten+downStreamWritten).
		Str("ExitId", cp.ExitId).Str("ConnId", cp.ConnId).Str("addr", addr).
		TimeDiff("Time", cp.Times.Connect, cp.Times.Total).
		Msg("Connection Done")
}

type ExitHandler struct {
	Listener net.Listener
	Exits    map[ExitId]Exit
}

func (e *ExitHandler) Listen(lnr net.Listener) {
	e.Listener = lnr
	log.Info().Str("Component", "exit").Str("bound", lnr.Addr().String()).Msg("Listening")
}

func (e *ExitHandler) Handler(w http.ResponseWriter, r *http.Request, conn *h2conn.Conn) {
	connId, ok := r.URL.Query()["connId"]
	if !ok || len(connId) < 1 || len(connId[0]) < 1 {
		log.Error().Str("Component", "exit").Str("remoteAddr", r.RemoteAddr).Msg("Url Param 'connId' is missing")
		return
	}
	exitIds, ok := r.URL.Query()["exitId"]
	if !ok || len(exitIds) < 1 || len(exitIds[0]) < 1 {
		log.Error().Str("ConnId", connId[0]).Msg("Url Param 'exitId' is missing")
		return
	}

	exit, ok := e.Exits[ExitId(exitIds[0])]
	if !ok {
		log.Error().Str("Component", "exit").Str("ConnId", connId[0]).Str("ExitId", string(exitIds[0])).Msg("Exit not found")
		return
	}
	connect(exit, ConnectParam{
		ExitId:   exitIds[0],
		ConnId:   connId[0],
		Request:  r,
		Response: w,
		Conn:     conn,
	})
}
