package main

import (
	"context"
	"github.com/tamen25/themis/internal/livewitness"
	"os"
	"os/signal"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(livewitness.Run(ctx, os.Args[1:], os.Stdout))
}
