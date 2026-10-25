package main

import (
	"crypto/sha256"
	"fmt"
)

func main() { fmt.Println(sha256.Sum256([]byte("synthetic gate control"))) }
