package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// version is stamped at link time (-X main.version, Makefile EXECUTOR_VERSION_FLAGS);
// `make verify-versions` checks it against VERSION.
var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("executor %s\n", version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
