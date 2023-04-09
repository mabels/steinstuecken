package drill

import (
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/mabels/steinstuecken/tunnel/endpoint"
	"github.com/mabels/steinstuecken/tunnel/h2"

	"github.com/rs/zerolog/log"
)

func Connect(tunnel *h2.Tunnel, ep endpoint.Bound) error {
	active := true
	for active {
		var conn endpoint.Conn
		conn, active = <-ep.Connections
		go func() {
			defer conn.Conn.Close()
			var err error
			url := fmt.Sprintf("%s?ep=%s&src=%s", tunnel.Config.UpStreamUrl, ep.ListenParam.Name, conn.Conn.RemoteAddr().String())
			// url := tunnel.Config.UpStreamUrl
			tunnel.Conn, tunnel.Resp, err = tunnel.Client.Connect(tunnel.Ctx, url)
			if err != nil {
				log.Error().Err(err).Msg("h2conn.Connect")
				return
			}
			defer tunnel.Conn.Close()
			// Check server status code
			if tunnel.Resp.StatusCode != http.StatusOK {
				log.Error().Msgf("Bad status code: %d", tunnel.Resp.StatusCode)
				return
			}
			wg := sync.WaitGroup{}
			var upStreamWritten, downStreamWritten int64
			wg.Add(1)
			go func() {
				upStreamWritten, err = io.Copy(tunnel.Conn, conn.Conn)
				if err != nil {
					wg.Done()
				} else {
					wg.Add(-1)
				}
			}()
			wg.Add(1)
			go func() {
				downStreamWritten, err = io.Copy(conn.Conn, tunnel.Conn)
				if err != nil {
					wg.Done()
				} else {
					wg.Add(-1)
				}
			}()
			wg.Wait()
			if err != nil {
				log.Error().Err(err).Msg(url)
				return
			}
			log.Info().Int64("upStreamWritten", upStreamWritten).Int64("downStreamWritten", downStreamWritten).Msg(url)
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
