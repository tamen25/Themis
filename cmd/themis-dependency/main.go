package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tamen25/themis/internal/dependencyexperiment"
	"github.com/tamen25/themis/internal/nativeexecution"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if len(os.Args) > 1 && (os.Args[1] == "approve-witnessed" || os.Args[1] == "run-witnessed") {
		os.Exit(nativeexecution.CLI(ctx, os.Args[1:], os.Stdout))
	}
	os.Exit(dependencyexperiment.CLI(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
