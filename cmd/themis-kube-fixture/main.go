// themis-kube-fixture is installed only by the disposable Kind setup. It has no
// Kubernetes credentials, dynamic destination, shell or networking privileges.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/tamen25/themis/internal/kubefault"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic fixture startup failed")
		os.Exit(1)
	}
}
func run() error {
	data, err := os.ReadFile("/etc/themis/config.json")
	if err != nil {
		return err
	}
	var config kubefault.Config
	if err = kubefault.Decode(data, &config); err != nil {
		return err
	}
	s, err := kubefault.NewServer(config, os.Getenv("POD_NAME"), os.Getenv("POD_UID"))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:8080")
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return s.Serve(ctx, listener)
}
