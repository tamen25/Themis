package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tamen25/themis/api/schemas"
)

const ExperimentSchemaVersion = "themis.contract/v1alpha2"

type Experiment struct {
	SchemaVersion string         `json:"schemaVersion"`
	Metadata      Metadata       `json:"metadata"`
	Spec          ExperimentSpec `json:"spec"`
}

type ExperimentSpec struct {
	Target      ExperimentTarget     `json:"target"`
	Execution   ExperimentExecution  `json:"execution"`
	Baseline    ObservationPhase     `json:"baseline"`
	Fault       LatencyFault         `json:"fault"`
	Observation InterventionWindow   `json:"observation"`
	Recovery    ObservationPhase     `json:"recovery"`
	Assertions  ExperimentAssertions `json:"assertions"`
	Evidence    ExperimentEvidence   `json:"evidence"`
	Cleanup     CleanupRequirement   `json:"cleanup"`
}
type ExperimentTarget struct {
	Kind    string `json:"kind"`
	Fixture string `json:"fixture"`
}
type ExperimentExecution struct {
	Profile             string `json:"profile"`
	MaxDuration         string `json:"maxDuration"`
	MaxConcurrentFaults int    `json:"maxConcurrentFaults"`
}
type ObservationPhase struct {
	Duration string `json:"duration"`
	Samples  int    `json:"samples"`
}
type LatencyFault struct {
	Type     string `json:"type"`
	Latency  string `json:"latency"`
	Duration string `json:"duration"`
}
type InterventionWindow struct {
	Samples      int `json:"samples"`
	MinConfirmed int `json:"minConfirmed"`
}
type ExperimentAssertions struct {
	MaximumErrorFraction json.Number `json:"maximumErrorFraction"`
}
type ExperimentEvidence struct {
	Intervention string `json:"intervention"`
	RawResponses bool   `json:"rawResponses"`
}
type CleanupRequirement struct {
	Required bool   `json:"required"`
	Timeout  string `json:"timeout"`
}

type ValidatedExperiment struct {
	data               Experiment
	normalized, digest string
}

func (v ValidatedExperiment) Digest() string         { return v.digest }
func (v ValidatedExperiment) NormalizedJSON() []byte { return []byte(v.normalized) }
func (v ValidatedExperiment) Snapshot() Experiment {
	c := v.data
	c.Metadata.Labels = maps.Clone(c.Metadata.Labels)
	return c
}

var experimentSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schemas.Experiment()))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(offlineLoader{})
	const location = "https://schemas.themis.invalid/contract/v1alpha2"
	if err := c.AddResource(location, doc); err != nil {
		return nil, err
	}
	return c.Compile(location)
})

func ParseExperiment(r io.Reader) (ValidatedExperiment, error) {
	v, err := parseDocument(r)
	if err != nil {
		return ValidatedExperiment{}, err
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return ValidatedExperiment{}, err
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		return ValidatedExperiment{}, err
	}
	schema, err := experimentSchema()
	if err != nil {
		return ValidatedExperiment{}, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	if err := schema.Validate(instance); err != nil {
		return ValidatedExperiment{}, fmt.Errorf("experiment schema: %w", err)
	}
	var c Experiment
	if err := json.Unmarshal(encoded, &c); err != nil {
		return ValidatedExperiment{}, err
	}
	if c.Metadata.Labels == nil {
		c.Metadata.Labels = map[string]string{}
	}
	fields := []*string{&c.Spec.Execution.MaxDuration, &c.Spec.Baseline.Duration, &c.Spec.Fault.Duration, &c.Spec.Fault.Latency, &c.Spec.Recovery.Duration, &c.Spec.Cleanup.Timeout}
	for _, field := range fields {
		d, err := duration("experiment duration", *field)
		if err != nil {
			return ValidatedExperiment{}, err
		}
		*field = d.String()
	}
	base, _ := time.ParseDuration(c.Spec.Baseline.Duration)
	fault, _ := time.ParseDuration(c.Spec.Fault.Duration)
	recovery, _ := time.ParseDuration(c.Spec.Recovery.Duration)
	budget, _ := time.ParseDuration(c.Spec.Execution.MaxDuration)
	if base+fault+recovery > budget {
		return ValidatedExperiment{}, fmt.Errorf("experiment phases exceed maxDuration")
	}
	if c.Spec.Observation.MinConfirmed > c.Spec.Observation.Samples {
		return ValidatedExperiment{}, fmt.Errorf("minConfirmed exceeds observation samples")
	}
	// v1alpha2 preserves exact decimals without float64 conversion. Choosing the
	// shorter exact spelling also keeps normalized literals within syntax bounds.
	c.Spec.Assertions.MaximumErrorFraction = json.Number(exactDecimal(c.Spec.Assertions.MaximumErrorFraction.String()))
	encoded, err = json.Marshal(c)
	if err != nil {
		return ValidatedExperiment{}, err
	}
	return ValidatedExperiment{c, string(encoded), fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))}, nil
}

func exactDecimal(raw string) string {
	parts := strings.Split(strings.ToLower(strings.TrimPrefix(raw, "-")), "e")
	exponent := 0
	if len(parts) == 2 {
		exponent, _ = strconv.Atoi(parts[1])
	}
	decimal := strings.Split(parts[0], ".")
	digits := decimal[0]
	if len(decimal) == 2 {
		digits += decimal[1]
		exponent -= len(decimal[1])
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0"
	}
	for strings.HasSuffix(digits, "0") {
		digits = strings.TrimSuffix(digits, "0")
		exponent++
	}
	decimalAt := func(point int) string {
		if point <= 0 {
			return "0." + strings.Repeat("0", -point) + digits
		}
		if point >= len(digits) {
			return digits + strings.Repeat("0", point-len(digits))
		}
		return digits[:point] + "." + digits[point:]
	}
	point := len(digits) + exponent
	best := decimalAt(point)
	choose := func(candidate string) {
		if len(candidate) < len(best) || (len(candidate) == len(best) && candidate < best) {
			best = candidate
		}
	}
	scientific := digits[:1]
	if len(digits) > 1 {
		scientific += "." + digits[1:]
	}
	if point-1 >= -400 && point-1 <= 400 {
		choose(scientific + "e" + strconv.Itoa(point-1))
	}
	if exponent >= -400 && exponent <= 400 {
		choose(digits + "e" + strconv.Itoa(exponent))
	}
	// Values such as 0.001e-400 must not normalize to an exponent rejected by
	// our own bounded syntax. A coefficient at the minimum exponent preserves
	// the original bound, including long exact literals near the size limit.
	choose(decimalAt(point+400) + "e-400")
	return best
}
