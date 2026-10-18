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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var handlers sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[*net.UnixConn]bool)
	fatal := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		local.listener.Close()
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
	}()
	defer func() {
		cancel()
		<-stopped
		handlers.Wait()
		select {
		case err := <-fatal:
			serveErr = err
		default:
		}
	}()
	for {
		conn, err := local.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				select {
				case err := <-fatal:
					return err
				default:
					return nil
				}
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
		connections[conn] = true
		mu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
			// Covers frame reads, the maximum await, and a stalled response consumer.
			conn.SetDeadline(time.Now().Add(90 * time.Second))
			if err := s.ServeConn(ctx, conn); errors.Is(err, securestate.ErrCommitUncertain) {
				select {
				case fatal <- err:
				default:
				}
				cancel()
			}
		}()
	}
}
