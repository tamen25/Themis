package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	"github.com/tamen25/themis/api/schemas"
)

const (
	MaxDocumentBytes = 1 << 20
	maxDepth         = 32
	maxNodes         = 10000
	maxDuration      = 10 * time.Minute
)

// ErrRead and ErrSchema distinguish I/O and compiler errors from invalid input.
var (
	ErrRead   = errors.New("read contract")
	ErrSchema = errors.New("compile embedded contract schema")
)

type offlineLoader struct{}

func (offlineLoader) Load(location string) (any, error) {
	return nil, fmt.Errorf("external schema resource forbidden: %s", location)
}

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schemas.Contract()))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(offlineLoader{})
	const location = "https://schemas.themis.invalid/contract/v1alpha1"
	if err := c.AddResource(location, doc); err != nil {
		return nil, err
	}
	return c.Compile(location)
})

// parseDocument is shared syntax handling; schema versions retain independent
// validation, normalization and hashing rules.
func parseDocument(r io.Reader) (any, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRead, err)
	}
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("contract exceeds %d bytes", MaxDocumentBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("parse trailing YAML: %w", err)
		}
		return nil, errors.New("expected exactly one YAML document")
	}
	if len(doc.Content) != 1 {
		return nil, errors.New("expected a contract object")
	}
	nodes := 0
	value, err := jsonValue(doc.Content[0], "$", 0, &nodes)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// Parse accepts exactly one bounded v1alpha1 YAML/JSON document, without I/O
// beyond the supplied reader. Its normalization and digest remain unchanged.
func Parse(r io.Reader) (Validated, error) {
	value, err := parseDocument(r)
	if err != nil {
		return Validated{}, err
	}
	if object, ok := value.(map[string]any); ok {
		if version, ok := object["schemaVersion"].(string); ok && version != SchemaVersion {
			return Validated{}, fmt.Errorf("unsupported schemaVersion %q; supported: %s", version, SchemaVersion)
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return Validated{}, fmt.Errorf("contract must contain JSON-compatible values: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		return Validated{}, fmt.Errorf("decode contract JSON: %w", err)
	}
	schema, err := compiledSchema()
	if err != nil {
		return Validated{}, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	if err := schema.Validate(instance); err != nil {
		return Validated{}, fmt.Errorf("contract schema: %w", err)
	}
	// Preserve exact numbers through schema validation. Only afterwards convert
	// to float64: the schema bounds every accepted numeric field to [0, 100000].
	// This also normalizes integral spellings such as minSamples: 1.0 to 1.
	var defaulted map[string]any
	if err := json.Unmarshal(encoded, &defaulted); err != nil {
		return Validated{}, fmt.Errorf("decode validated contract: %w", err)
	}
	applyDefaults(defaulted)
	encoded, err = json.Marshal(defaulted)
	if err != nil {
		return Validated{}, fmt.Errorf("encode defaulted contract: %w", err)
	}
	var c Contract
	if err := json.Unmarshal(encoded, &c); err != nil {
		return Validated{}, fmt.Errorf("decode typed contract: %w", err)
	}
	if err := normalize(&c); err != nil {
		return Validated{}, err
	}
	normalized, err := json.Marshal(c)
	if err != nil {
		return Validated{}, fmt.Errorf("encode normalized contract: %w", err)
	}
	return Validated{data: c, normalized: string(normalized), digest: fmt.Sprintf("sha256:%x", sha256.Sum256(normalized))}, nil
}

// Convert the YAML syntax tree without alias expansion, implicit key coercion,
// merge semantics or last-key-wins behavior at any nesting level.
func jsonValue(n *yaml.Node, path string, depth int, nodes *int) (any, error) {
	(*nodes)++
	if depth > maxDepth || *nodes > maxNodes {
		return nil, fmt.Errorf("%s: YAML exceeds depth or node limit", path)
	}
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return nil, fmt.Errorf("%s: YAML anchors and aliases are unsupported", path)
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			break
		}
		object := make(map[string]any, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
				return nil, fmt.Errorf("%s: mapping keys must be plain strings; merge keys are unsupported", path)
			}
			if _, exists := object[key.Value]; exists {
				return nil, fmt.Errorf("%s: duplicate field %q", path, key.Value)
			}
			value, err := jsonValue(n.Content[i+1], path+"."+key.Value, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			object[key.Value] = value
		}
		return object, nil
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			break
		}
		array := make([]any, len(n.Content))
		for i, child := range n.Content {
			value, err := jsonValue(child, fmt.Sprintf("%s[%d]", path, i), depth+1, nodes)
			if err != nil {
				return nil, err
			}
			array[i] = value
		}
		return array, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
			numeric := n.Tag == "!!int" || n.Tag == "!!float"
			if numeric {
				if len(n.Value) > 64 {
					return nil, fmt.Errorf("%s: numeric literals must not exceed 64 characters", path)
				}
				if i := strings.IndexAny(n.Value, "eE"); i >= 0 {
					exponent, err := strconv.Atoi(n.Value[i+1:])
					if err != nil || exponent < -400 || exponent > 400 {
						return nil, fmt.Errorf("%s: numeric exponent must be between -400 and 400", path)
					}
				}
			}
			var value any
			if err := n.Decode(&value); err != nil {
				return nil, fmt.Errorf("%s: invalid scalar: %w", path, err)
			}
			if numeric {
				// json.Marshal rejects non-JSON forms, including NaN, infinity,
				// hex, underscores and leading-dot fractions. No precision is lost.
				return json.Number(n.Value), nil
			}
			return value, nil
		}
	}
	return nil, fmt.Errorf("%s: unsupported YAML type %q", path, n.Tag)
}

func defaultValue(object map[string]any, key string, value any) {
	if _, exists := object[key]; !exists {
		object[key] = value
	}
}

func applyDefaults(root map[string]any) {
	defaultValue(root["metadata"].(map[string]any), "labels", map[string]any{})
	spec := root["spec"].(map[string]any)
	execution := spec["execution"].(map[string]any)
	defaultValue(execution, "profile", "local")
	defaultValue(execution, "maxConcurrentFaults", 0)
	defaultValue(execution, "requireApproval", true)
	defaultValue(spec, "evidence", map[string]any{})
	evidence := spec["evidence"].(map[string]any)
	defaultValue(evidence, "includeRawTraces", false)
	defaultValue(evidence, "requireSignature", false)
	for _, raw := range spec["assertions"].([]any) {
		assertion := raw.(map[string]any)
		defaultValue(assertion, "required", true)
		defaultValue(assertion, "minSamples", 1)
	}
}

func duration(field string, text string) (time.Duration, error) {
	d, err := time.ParseDuration(text)
	if err != nil || d < time.Millisecond || d > maxDuration {
		return 0, fmt.Errorf("%s: duration must be between 1ms and 10m using Go duration syntax", field)
	}
	return d, nil
}

func normalize(c *Contract) error {
	endpoint, err := localURL(c.Spec.Target.URL)
	if err != nil {
		return fmt.Errorf("spec.target.url: %w", err)
	}
	c.Spec.Target.URL = endpoint
	limit, err := duration("spec.execution.maxDuration", c.Spec.Execution.MaxDuration)
	if err != nil {
		return err
	}
	c.Spec.Execution.MaxDuration = limit.String()
	names := make(map[string]bool)
	var total time.Duration
	for i := range c.Spec.Scenario.Phases {
		phase := &c.Spec.Scenario.Phases[i]
		if names[phase.Name] {
			return fmt.Errorf("spec.scenario.phases: duplicate name %q", phase.Name)
		}
		names[phase.Name] = true
		d, err := duration(fmt.Sprintf("spec.scenario.phases[%d].duration", i), phase.Duration)
		if err != nil {
			return err
		}
		phase.Duration = d.String()
		total += d // At most 16 phases of 10m; cannot overflow time.Duration.
	}
	if total > limit {
		return errors.New("spec.scenario.phases: total duration exceeds spec.execution.maxDuration")
	}
	ids := make(map[string]bool)
	required := false
	for i := range c.Spec.Assertions {
		a := &c.Spec.Assertions[i]
		if ids[a.ID] {
			return fmt.Errorf("spec.assertions: duplicate id %q", a.ID)
		}
		ids[a.ID] = true
		required = required || a.Required
		if a.Deadline != "" {
			d, err := duration(fmt.Sprintf("spec.assertions[%d].deadline", i), a.Deadline)
			if err != nil {
				return err
			}
			if d > total {
				return fmt.Errorf("spec.assertions[%d].deadline: exceeds scenario duration", i)
			}
			a.Deadline = d.String()
		}
		if a.MaximumErrorFraction != nil && *a.MaximumErrorFraction == 0 {
			*a.MaximumErrorFraction = 0 // Canonicalize negative zero.
		}
	}
	if !required {
		return errors.New("spec.assertions: at least one required assertion is necessary")
	}
	sort.Slice(c.Spec.Assertions, func(i, j int) bool { return c.Spec.Assertions[i].ID < c.Spec.Assertions[j].ID })
	return nil
}

func localURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid URL")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", errors.New("expected an HTTP(S) URL without credentials, query or fragment")
	}
	address, err := netip.ParseAddr(u.Hostname())
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return "", errors.New("host must be a literal loopback IP (127.0.0.0/8 or ::1); DNS names are unsupported")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("an explicit port between 1 and 65535 is required")
	}
	u.Host = net.JoinHostPort(address.String(), strconv.Itoa(port))
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}
