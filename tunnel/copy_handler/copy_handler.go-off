package copy_handler

import (
	"fmt"
	"io"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type CopyHandler struct {
	ExitId       string
	ConnId       string
	Addr         string
	Buf          []byte
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type ResultCopy struct {
	Written int64
	Read    int64
	Error   error
}

type actionCmd struct {
	reader io.Reader
	writer io.Writer
	buffer []byte
	result struct {
		len int
		err error
	}
}

func defaultTimeout(d time.Duration) time.Duration {
	if d == 0 {
		return time.Duration(time.Hour)
	}
	return d
}

func (wt *withTimeout) actionHandler() {
	readCmds := 0
	writeCmds := 0
	for {
		select {
		case cmd, done := <-wt.cmds:
			if !done {
				wt.logCtx(log.Info()).
					Int("readCmds", readCmds).
					Int("writeCmds", writeCmds).
					Msg("actionHandler done")
				return
			}
			if cmd.reader != nil {
				readCmds++
				cmd.result.len, cmd.result.err = cmd.reader.Read(cmd.buffer)
				wt.results <- cmd
			} else if cmd.writer != nil {
				writeCmds++
				cmd.result.len, cmd.result.err = cmd.writer.Write(cmd.buffer)
				wt.results <- cmd
			} else {
				wt.logCtx(log.Fatal()).Msg("reader and writer are nil")
			}
		}
	}

}

func (wt *withTimeout) cmdWithTimeout(cmd actionCmd, timeout time.Duration) (int, error) {
	wt.cmds <- cmd
	select {
	case cmd, done := <-wt.results:
		if !done {
			wt.logCtx(log.Fatal()).Msg("results channel closed")
		}
		if !(cmd.result.err == nil || cmd.result.err == io.EOF) {
			wt.logCtx(log.Error()).Err(cmd.result.err).Msg("read-upstream")
			return 0, cmd.result.err
		}
		return cmd.result.len, cmd.result.err
	case <-time.After(defaultTimeout(timeout)):
		err := fmt.Errorf("ReadTimeout:%d", defaultTimeout(timeout))
		wt.logCtx(log.Error()).Err(err).Msg("timeout on src")
		return 0, err
	}
	panic("unreachable")
}

type withTimeout struct {
	cmds    chan actionCmd
	results chan actionCmd
	logCtx  func(in *zerolog.Event) *zerolog.Event
}

func (wt *withTimeout) close() {
	close(wt.cmds)
	close(wt.results)
	wt.logCtx(log.Info()).Msg("close withTimeout")
}

func newWithTimeout(logCtx func(in *zerolog.Event) *zerolog.Event) withTimeout {
	wt := withTimeout{
		cmds:    make(chan actionCmd, 2),
		results: make(chan actionCmd, 2),
		logCtx:  logCtx,
	}
	go wt.actionHandler()
	wt.logCtx(log.Info()).Msg("start withTimeout")
	return wt
}

func (ch *CopyHandler) Copy(dst io.Writer, src io.Reader) ResultCopy {
	res := ResultCopy{}
	// might not the best way to do this

	logCtx := func(ev *zerolog.Event) *zerolog.Event {
		return ev.Str("Component", "copy").Str("ExitId", ch.ExitId).Str("ConnId", ch.ConnId).Str("addr", ch.Addr)
	}
	wt := newWithTimeout(logCtx)

	defer wt.close()
	for stopLoop := false; !stopLoop; {
		rlen, err := wt.cmdWithTimeout(actionCmd{reader: src, buffer: ch.Buf}, ch.ReadTimeout)
		if err == io.EOF {
			stopLoop = true
			logCtx(log.Info()).Msg("copy done")
		} else if err != nil {
			res.Error = err
			logCtx(log.Error()).Err(err).Msg("copy src with error")
			break
		}
		res.Read += int64(rlen)
		wlen, err := wt.cmdWithTimeout(actionCmd{writer: dst, buffer: ch.Buf}, ch.WriteTimeout)
		if err != nil {
			res.Error = err
			logCtx(log.Error()).Err(err).Msg("copy dst with error")
			break
		}
		res.Written += int64(wlen)
	}
	return res
}
