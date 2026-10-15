package fixture

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
)

func testIdentity() plan.FixtureIdentity {
	return plan.FixtureIdentity{Name: "demo", InstanceID: strings.Repeat("1", 64), ServiceID: strings.Repeat("2", 64), ProxyID: strings.Repeat("3", 64), EvidenceKey: strings.Repeat("4", 64), OwnerUID: "owner", Host: "host", PID: 1, ServiceURL: "http://127.0.0.1:1", ProxyURL: "http://127.0.0.1:2", ControlURL: "http://127.0.0.1:3", AdapterVersion: localpolicy.AdapterVersion, ExpiresAt: time.Now().Add(time.Minute).UTC()}
}

func TestControlProofRejectsReplayAndTampering(t *testing.T) {
	token := localstate.RandomID()
	id := testIdentity()
	a := &authority{identity: id, config: WorkerConfig{Credentials: Credentials{ControlToken: token}}, nonces: map[string]bool{}}
	data := []byte(`{}`)
	nonce := localstate.RandomID()
	proof := mac(token, requestProof(id.InstanceID, "/status", nonce, data))
	request := func(body []byte, nonce, proof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/status", bytes.NewReader(body))
		req.Header.Set("X-Themis-Nonce", nonce)
		req.Header.Set("X-Themis-Signature", proof)
		w := httptest.NewRecorder()
		a.control(w, req)
		return w
	}
	valid := request(data, nonce, proof)
	if valid.Code != 200 {
		t.Fatal("valid request rejected")
	}
	var response controlResponse
	if err := json.Unmarshal(valid.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	signature := response.MAC
	response.MAC = ""
	if !validMAC(token, response, signature) || response.Nonce != nonce {
		t.Fatal("unsigned response")
	}
	if request(data, nonce, proof).Code != 403 {
		t.Fatal("replayed control mutation accepted")
	}
	if request([]byte(`{"changed":true}`), localstate.RandomID(), proof).Code != 403 {
		t.Fatal("tampered request accepted")
	}
	if a.applyCount != 0 {
		t.Fatal("denial mutated fault")
	}
}

func TestReplacementListenerCannotLearnControlKeyOrForgeResult(t *testing.T) {
	token := localstate.RandomID()
	id := testIdentity()
	id.EvidenceKey = hex.EncodeToString(evidencePrivateKey(token)[32:])
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity" {
			proof := IdentityProof{Version: Version, Identity: id, Nonce: r.URL.Query().Get("nonce")}
			proof.MAC = mac(token, proof)
			writeJSON(w, 200, proof)
			return
		}
		calls++
		if strings.Contains(fmtHeaders(r.Header), token) {
			t.Error("control key disclosed to replacement listener")
		}
		writeJSON(w, 200, Status{Identity: id}) // no response proof
	}))
	defer server.Close()
	id.ControlURL = server.URL
	h, transport := NewHTTPClient()
	defer transport.CloseIdleConnections()
	c := &Client{Identity: id, credentials: Credentials{ControlToken: token}, http: h, transport: transport}
	if _, err := c.Status(context.Background()); err == nil || calls != 1 {
		t.Fatal("replacement listener's response trusted")
	}
}

func fmtHeaders(h http.Header) string {
	var value strings.Builder
	for k, v := range h {
		value.WriteString(k)
		for _, s := range v {
			value.WriteString(s)
		}
	}
	return value.String()
}

func TestReadOnlyInspectionDoesNotConsumeControlState(t *testing.T) {
	token := localstate.RandomID()
	id := testIdentity()
	a := &authority{identity: id, config: WorkerConfig{Credentials: Credentials{ControlToken: token}}, nonces: map[string]bool{}}
	for range 10 {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/inspect?nonce="+localstate.RandomID(), nil)
		w := httptest.NewRecorder()
		a.control(w, req)
		if w.Code != 200 {
			t.Fatal("read-only inspection rejected")
		}
	}
	if len(a.nonces) != 0 || len(a.events) != 0 || a.applyCount != 0 {
		t.Fatal("inspection mutated control state")
	}
}
