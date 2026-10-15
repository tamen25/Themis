// A disposable status-only fixture. It is never started by themis run.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"
)

func main() {
	status := flag.Int("status", 200, "health status (200 or 503)")
	address := flag.String("listen", "127.0.0.1:8080", "literal loopback address and port")
	flag.Parse()
	if (*status != 200 && *status != 503) || flag.NArg() != 0 {
		log.Fatal("use -status 200 or -status 503")
	}
	endpoint, err := netip.ParseAddrPort(*address)
	if err != nil || !endpoint.Addr().IsLoopback() {
		log.Fatal("-listen requires a literal loopback address and port")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(*status)
		fmt.Fprintln(w, http.StatusText(*status))
	})
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second}
	log.Printf("disposable fixture on http://%s/health (status %d)", listener.Addr(), *status)
	log.Fatal(server.Serve(listener))
}
