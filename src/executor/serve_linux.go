//go:build linux

package executor

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
)

// Serve owns connection lifetimes. An uncertain commit stops acceptance and
// returns a fatal error to the process owner; it never reopens the store.
func (s *Service) Serve(ctx context.Context, local *Local) (serveErr error) {
	s.startWaiter()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var handlers sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[*net.UnixConn]bool)
	var fatalErr error
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case fatalErr = <-s.fatal:
			cancel()
		case <-ctx.Done():
		}
		local.listener.Close()
		s.Close()
		mu.Lock()
		drainDeadline := time.Now().Add(time.Second)
		for conn := range connections {
			// Wake incomplete frames while allowing committed replies to finish.
			conn.SetReadDeadline(time.Now())
			conn.SetWriteDeadline(drainDeadline)
		}
		mu.Unlock()
	}()
	defer func() {
		cancel()
		<-stopped
		handlers.Wait()
		if fatalErr != nil {
			serveErr = fatalErr
			return
		}
		select {
		case err := <-s.fatal:
			serveErr = err
		default:
		}
	}()
	for {
		conn, err := local.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, errPeerRefused) {
				continue
			}
			return err
		}
		mu.Lock()
		if ctx.Err() != nil {
			conn.Close()
			mu.Unlock()
			continue
		}
		// Initialize before publishing so shutdown deadlines cannot be overwritten.
		conn.SetDeadline(time.Now().Add(90 * time.Second))
		connections[conn] = true
		mu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
			if err := s.ServeConn(ctx, conn); errors.Is(err, securestate.ErrCommitUncertain) {
				s.reportFatal(err)
				cancel()
			}
		}()
	}
}

// reportFatal keeps storage failure delivery independent of caller lifetimes.
func (s *Service) reportFatal(err error) {
	select {
	case s.fatal <- err:
	default:
	}
}
