//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/karthikeyan5/sshgate/src/executor"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

func run(ctx context.Context) error {
	root, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	root = filepath.Join(root, "sshgate")
	local, err := executor.OpenLocal(os.Getenv("XDG_RUNTIME_DIR"), root)
	if err != nil {
		return err
	}
	defer local.Close()
	store, err := local.OpenJobStore()
	if err != nil {
		return err
	}
	defer store.Close()
	servers, err := registry.New(filepath.Join(root, "servers.json"))
	if err != nil {
		return err
	}
	gatePath := os.Getenv("SSHGATE_GATE_BIN")
	if gatePath == "" {
		gatePath = filepath.Join(root, "bin", "sshgate-gate-linux-amd64")
	}
	service, err := executor.NewService(executor.Config{Store: store, Servers: servers, StagedGatePath: gatePath})
	if err != nil {
		return err
	}
	return service.Serve(ctx, local)
}
