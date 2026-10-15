// Package schemas contains the versioned, embedded contract schema.
package schemas

import _ "embed"

//go:embed contract-v1alpha1.json
var contractSchema string

// Contract returns the schema used by the contract compiler, without filesystem I/O.
func Contract() string { return contractSchema }

//go:embed contract-v1alpha2.json
var experimentSchema string

func Experiment() string { return experimentSchema }
