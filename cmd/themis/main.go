package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/tamen25/themis/internal/cli"
	"github.com/tamen25/themis/internal/fixture"
)

// Set at release build time with -ldflags "-X main.version=v0.x.y".
var version = "dev"

func main() {
	os.Exit(execute())
}

func execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) == 2 && os.Args[1] == fixture.HiddenCommand {
		if err := fixture.Worker(ctx, os.Stdin); err != nil {
			return 6
		}
		return 0
	}
	return cli.RunContext(ctx, os.Args[1:], os.Stdout, os.Stderr, version)
}
