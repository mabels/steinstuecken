package main

import (
	"github.com/mabels/steinstuecken/testutils"
	"github.com/mabels/steinstuecken/tunnel/config"
	"github.com/mabels/steinstuecken/tunnel/drill"
	"github.com/mabels/steinstuecken/tunnel/endpoint"
	"github.com/mabels/steinstuecken/tunnel/h2"

	// "github.com/gobwas/ws"
	// "github.com/gobwas/ws/wsutil"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type MyReader struct {
	input chan []byte
}

func (r *MyReader) Read(p []byte) (n int, err error) {
	data := <-r.input
	copy(p, data)
	return len(data), nil
}

func (r *MyReader) Close() error {
	return nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	ssnc := config.SsnConfig{
		Client: config.SsnConfigClient{
			UpStreamUrl: "https://localhost:8000/",
		},
	}
	var cleanFn func()
	var err error
	ssnc.Client.CertFile, ssnc.Client.KeyFile, cleanFn, err = testutils.GenerateX509()
	if err != nil {
		log.Fatal().Err(err).Msg("GenerateX509")
	}
	defer cleanFn()

	go func() {
		h2.H2connServer(ssnc.Client.CertFile, ssnc.Client.KeyFile)
	}()
	// time.Sleep(time.Second)

	tunnel, err := h2.ConnectTunnel(ssnc.Client)
	if err != nil {
		log.Fatal().Err(err).Msg("ConnectTunnel")
	}

	endpoint, err := endpoint.BindEndpoint(endpoint.ListenParam{
		Name: "testConnection",
		Addr: "[::]:4711",
		Type: "tcp6",
	})
	if err != nil {
		log.Fatal().Err(err).Msg("BindEndpoint")
	}

	drill.Connect(&tunnel, endpoint)

	// defer cleanFn()
	// server := &h2.Server{}
	// fmt.Println("Server initializing")
	// go func() {
	// 	server.Initialize(certFile, keyFile)
	// }()
	// time.Sleep(1 * time.Second)
	// fmt.Println("Server started")
	// client := &h2.Client{}
	// fmt.Println("Dialing")
	// client.Dial(certFile, keyFile)
	// fmt.Println("Dialed")

	// myInput := MyReader{input: make(chan []byte, 1024)}
	// go func() {
	// 	cnt := 0
	// 	for {
	// 		myInput.input <- []byte(fmt.Sprintf("Hello-%d", cnt))
	// 		time.Sleep(1 * time.Second)
	// 	}
	// }()

	// client.Post(&myInput)
	// fmt.Println("Posted")

	// http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	conn, _, _, err := ws.UpgradeHTTP(r, w)
	// 	if err != nil {
	// 		// handle error
	// 	}
	// 	go func() {
	// 		defer conn.Close()

	// 		for {
	// 			msg, op, err := wsutil.ReadClientData(conn)
	// 			if err != nil {
	// 				// handle error
	// 			}
	// 			err = wsutil.WriteServerMessage(conn, op, msg)
	// 			if err != nil {
	// 				// handle error
	// 			}
	// 		}
	// 	}()
	// }))
}
