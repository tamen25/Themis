package main

import (
	"errors"
	"flag"
	"testing"
)

func TestExplicitConfigurationAndHelp(t *testing.T) {
	if err := run([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help: %v", err)
	}
	for _, args := range [][]string{nil, {"--namespace=default"}, {"--force"}, {"unexpected"}} {
		if err := run(args); err == nil {
			t.Fatalf("unconfigured controller started: %v", args)
		}
	}
}
