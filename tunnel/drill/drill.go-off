package drill

import (
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/mabels/steinstuecken/tunnel/copy_handler"
	"github.com/mabels/steinstuecken/tunnel/endpoint"
	"github.com/mabels/steinstuecken/tunnel/h2"

	"github.com/rs/zerolog/log"
)

type DrillTime struct {
	Start   time.Time
	Connect time.Time
	InCopy  time.Time
	OutCopy time.Time
	Total   time.Time
}

func Connect(tunnel *h2.Tunnel, ep endpoint.Bound) error {
	active := true
	for active {
		var conn endpoint.Conn
		conn, active = <-ep.Connections
		dt := DrillTime{Start: time.Now()}
		go func() {
			connId := uuid.NewString()
			defer conn.Conn.Close()
			// var err error
			url, err := url.Parse(tunnel.Config.UpStreamUrl)
			if err != nil {
				log.Error().Str("Component", "drill").Str("url", tunnel.Config.UpStreamUrl).Str("connId", connId).Err(err).Msg("url.Parse")
				return
			}
			qry := url.Query()
			qry.Add("connId", connId)
			qry.Add("exitId", ep.ListenParam.Name)
			url.RawQuery = qry.Encode()

			tunnel.Conn, tunnel.Resp, err = tunnel.Client.Connect(tunnel.Ctx, url.String())
			if err != nil {
				log.Error().Str("Component", "drill").Err(err).Msg("h2conn.Connect")
				return
			}
			defer tunnel.Conn.Close()
			dt.Connect = time.Now()
			log.Info().Str("Component", "drill").Str("ExitId", ep.ListenParam.Name).Str("ConnId", connId).
				TimeDiff("Time", dt.Start, dt.Connect).Msg("Connect")
			// Check server status code
			if tunnel.Resp.StatusCode != http.StatusOK {
				log.Error().Str("Component", "drill").Str("ExitId", ep.ListenParam.Name).Str("ConnId", connId).Msgf("Bad status code: %d", tunnel.Resp.StatusCode)
				return
			}
			out := make(chan copy_handler.ResultCopy, 2)
			go func() {
				ch := copy_handler.CopyHandler{
					ExitId: ep.ListenParam.Name,
					ConnId: connId,
					Addr:   url.String(),
					Buf:    make([]byte, tunnel.Config.BufferSize()),
				}
				result := ch.Copy(tunnel.Conn, conn.Conn)
				out <- result
				dt.InCopy = time.Now()
				log.Info().Str("Component", "drill").
					Str("ExitId", ep.ListenParam.Name).Str("ConnId", connId).
					Err(result.Error).
					Int64("UpStreamWritten", result.Written).
					TimeDiff("Time", dt.Connect, dt.InCopy).Msg("InCopy Done")
			}()
			go func() {
				ch := copy_handler.CopyHandler{
					ExitId: ep.ListenParam.Name,
					ConnId: connId,
					Addr:   url.String(),
					Buf:    make([]byte, tunnel.Config.BufferSize()),
				}
				result := ch.Copy(conn.Conn, tunnel.Conn)
				out <- result
				dt.OutCopy = time.Now()
				log.Info().Str("Component", "drill").
					Str("ExitId", ep.ListenParam.Name).Str("ConnId", connId).
					Err(result.Error).
					Int64("DownStreamWritten", result.Written).
					TimeDiff("Time", dt.OutCopy, dt.Connect).Msg("OutCopy Done")
			}()
			select {
			case result, done := <-out:
				if !done {
				}
			}
			dt.Total = time.Now()
			log.Info().
				Str("Component", "drill").
				Str("ExitId", ep.ListenParam.Name).Str("ConnId", connId).
				Int64("totalTransfered", upStreamWritten+downStreamWritten).
				TimeDiff("Time", dt.Start, dt.Total).Msg("Done")
		}()
	}
	return nil

	// Loop until user terminates
	// fmt.Println("Echo session starts, press ctrl-C to terminate.")
	// cnt := 0
	// for ctx.Err() == nil {

	// 	// Ask the user to give a message to send to the server
	// 	// fmt.Print("Send: ")
	// 	// msg, err := stdin.ReadString('\n')
	// 	// if err != nil {
	// 	// 	log.Fatalf("Failed reading stdin: %v", err)
	// 	// }
	// 	// msg = strings.TrimRight(msg, "\n")
	// 	msg := fmt.Sprintf("jojo:%d\n", cnt)
	// 	cnt += 1

	// 	// Send the message to the server
	// 	err = out.Encode(msg)
	// 	if err != nil {
	// 		log.Fatalf("Failed sending message: %v", err)
	// 	}

	// 	// Receive the response from the server
	// 	var resp string
	// 	err = in.Decode(&resp)
	// 	if err != nil {
	// 		log.Fatalf("Failed receiving message: %v", err)
	// 	}

	// 	fmt.Printf("Got response %q\n", resp)
	// 	time.Sleep(time.Second)
	// }
}
