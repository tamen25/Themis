// Package contract validates and normalizes portable reliability contracts.
package contract

import (
	"maps"
	"slices"
)

const SchemaVersion = "themis.contract/v1alpha1"

// Contract is the normalized T0 schema. Construct a Validated contract with Parse.
type Contract struct {
	SchemaVersion string   `json:"schemaVersion"`
	Metadata      Metadata `json:"metadata"`
	Spec          Spec     `json:"spec"`
}

type Metadata struct {
	Name   string            `json:"name"`
	Owner  string            `json:"owner"`
	Labels map[string]string `json:"labels"`
}

type Spec struct {
	Target     Target      `json:"target"`
	Execution  Execution   `json:"execution"`
	Scenario   Scenario    `json:"scenario"`
	Assertions []Assertion `json:"assertions"`
	Evidence   Evidence    `json:"evidence"`
}

type Target struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Execution struct {
	Profile             string `json:"profile"`
	MaxDuration         string `json:"maxDuration"`
	MaxConcurrentFaults int    `json:"maxConcurrentFaults"`
	RequireApproval     bool   `json:"requireApproval"`
}

type Scenario struct {
	ID     string  `json:"id"`
	Phases []Phase `json:"phases"`
}

type Phase struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
}

type Assertion struct {
	ID                   string   `json:"id"`
	Type                 string   `json:"type"`
	Required             bool     `json:"required"`
	MinSamples           int      `json:"minSamples"`
	Deadline             string   `json:"deadline,omitempty"`
	MaximumErrorFraction *float64 `json:"maximumErrorFraction,omitempty"`
}

type Evidence struct {
	IncludeRawTraces bool `json:"includeRawTraces"`
	RequireSignature bool `json:"requireSignature"`
}

// Validated owns an immutable normalized snapshot. Its zero value is invalid.
type Validated struct {
	data       Contract
	normalized string
	digest     string
}

func (v Validated) Digest() string { return v.digest }

// NormalizedJSON returns a fresh copy of the bytes covered by Digest.
func (v Validated) NormalizedJSON() []byte { return []byte(v.normalized) }

// Snapshot returns an independent copy, including all nested reference values.
func (v Validated) Snapshot() Contract {
	c := v.data
	c.Metadata.Labels = maps.Clone(c.Metadata.Labels)
	c.Spec.Scenario.Phases = slices.Clone(c.Spec.Scenario.Phases)
	c.Spec.Assertions = slices.Clone(c.Spec.Assertions)
	for i := range c.Spec.Assertions {
		if fraction := c.Spec.Assertions[i].MaximumErrorFraction; fraction != nil {
			copy := *fraction
			c.Spec.Assertions[i].MaximumErrorFraction = &copy
		}
	}
	return c
}
