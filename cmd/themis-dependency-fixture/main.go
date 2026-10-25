package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
)

func main() {
	role := flag.String("role", "", "application, proxy or dependency")
	config := flag.String("config", "/config/config.json", "installer config")
	state := flag.String("state", "/state", "bounded private proxy state")
	flag.Parse()
	b, e := os.ReadFile(*config)
	var c dependencyhttp.Config
	if e == nil {
		e = localstate.Unmarshal(b, &c)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "installer config denied")
		os.Exit(5)
	}
	s, e := dependencyhttp.NewServer(c, *role, os.Getenv("POD_UID"), *state)
	if e != nil {
		fmt.Fprintln(os.Stderr, "fixture startup denied")
		os.Exit(5)
	}
	defer s.Close()
	server := &http.Server{Addr: ":8080", Handler: s, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
	if e = server.ListenAndServe(); e != nil {
		fmt.Fprintln(os.Stderr, "fixture server stopped")
		os.Exit(3)
	}
}
