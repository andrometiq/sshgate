// fake-telegram runs two loopback-only HTTP listeners inside the controller.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/tests/journey/faketg"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func listen(address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("listener must use a loopback IP")
	}
	return net.Listen("tcp", address)
}
func run() error {
	apiAddress := flag.String("api", "127.0.0.1:0", "Bot API listen address")
	adminAddress := flag.String("admin", "127.0.0.1:0", "controller admin listen address")
	user := flag.Int64("user-id", 99999, "synthetic operator ID")
	flag.Parse()
	if *user == 0 {
		return fmt.Errorf("user-id must be nonzero")
	}
	api, err := listen(*apiAddress)
	if err != nil {
		return err
	}
	defer api.Close()
	admin, err := listen(*adminAddress)
	if err != nil {
		return err
	}
	defer admin.Close()
	service := faketg.New(*user)
	servers := []*http.Server{{Handler: http.HandlerFunc(service.API), ReadHeaderTimeout: 5 * time.Second}, {Handler: http.HandlerFunc(service.Admin), ReadHeaderTimeout: 5 * time.Second}}
	failures := make(chan error, 2)
	go func() { failures <- servers[0].Serve(api) }()
	go func() { failures <- servers[1].Serve(admin) }()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"api_url": "http://" + api.Addr().String(), "admin_url": "http://" + admin.Addr().String()}); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err = <-failures:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, server := range servers {
		if e := server.Shutdown(shutdown); e != nil {
			return e
		}
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
