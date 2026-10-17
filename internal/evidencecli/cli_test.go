package evidencecli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
)

func TestExplicitSigningKeyStorageAndNoDisclosure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "signer")
	var out bytes.Buffer
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	if code := run([]string{"keygen", "--key-dir", dir, "--publisher", "test-operator"}, &out, now); code != 0 {
		t.Fatal(code, out.String())
	}
	var p evidence.Publisher
	if json.Unmarshal(out.Bytes(), &p) != nil || p.Algorithm != evidence.Algorithm {
		t.Fatal("public key output invalid")
	}
	if e := localstate.Check(dir); e != nil {
		t.Fatal("signer directory is not protected", e)
	}
	path := filepath.Join(dir, "signer-key.json")
	if e := localstate.Check(path); e != nil {
		t.Fatal("signer key is not protected", e)
	}
	var k keyRecord
	if e := localstate.Read(path, &k); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{base64.StdEncoding.EncodeToString(k.PrivateKey), base64.StdEncoding.EncodeToString(k.PrivateKey[:ed25519.SeedSize])} {
		if bytes.Contains(out.Bytes(), []byte(value)) {
			t.Fatal("signing key disclosed")
		}
	}
	before, _ := os.ReadFile(path)
	out.Reset()
	if code := run([]string{"keygen", "--key-dir", dir, "--publisher", "test-operator"}, &out, now); code == 0 {
		t.Fatal("existing key replaced")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key changed")
	}
}

func TestCLIStableErrorsAndNoImplicitTrust(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{{nil, 2}, {[]string{"run"}, 2}, {[]string{"verify", "--bundle", "arbitrary.zip"}, 5}, {[]string{"inspect", "--bundle", "missing.zip"}, 3}, {[]string{"bundle", "--source", "missing"}, 2}, {[]string{"verify", "--bundle", "x", "--trust-policy", "x", "--endpoint", "http://127.0.0.1:1"}, 2}} {
		var b bytes.Buffer
		if got := Run(tc.args, &b); got != tc.want {
			t.Fatal(tc.args, got, b.String())
		}
		if !json.Valid(b.Bytes()) {
			t.Fatal("error output is not JSON")
		}
	}
}
