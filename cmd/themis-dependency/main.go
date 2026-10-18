package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tamen25/themis/internal/dependencyexperiment"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	os.Exit(dependencyexperiment.CLI(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
