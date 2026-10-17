package evidence

import (
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestPublishedManifestSchemaMatchesWireObject(t *testing.T) {
	m, f, k, _ := fixture(t)
	b, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	_, mb, _ := unpack(t, b)
	schema, e := jsonschema.NewCompiler().Compile("../../schemas/evidence-bundle-v1alpha1.json")
	if e != nil {
		t.Fatal(e)
	}
	var v any
	if e = json.Unmarshal(mb, &v); e != nil {
		t.Fatal(e)
	}
	if e = schema.Validate(v); e != nil {
		t.Fatal("wire manifest differs from published schema", e)
	}
	object := v.(map[string]any)
	object["undeclared"] = true
	if e = schema.Validate(object); e == nil {
		t.Fatal("schema permits unknown executable metadata")
	}
}
