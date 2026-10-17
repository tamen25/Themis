package main

import (
	"github.com/tamen25/themis/internal/evidencecli"
	"os"
)

func main() { os.Exit(evidencecli.Run(os.Args[1:], os.Stdout)) }
