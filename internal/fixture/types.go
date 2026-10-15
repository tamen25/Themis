// Package fixture owns the disposable service, proxy and local authorization authority.
package fixture

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/safety"
)

const Version = "themis.fixture/v2"
const HiddenCommand = "_fixture-worker"

type Credentials struct {
	ControlToken string `json:"controlToken"`
	DataToken    string `json:"dataToken"`
}
type WorkerConfig struct {
	Directory   string           `json:"directory"`
	Name        string           `json:"name"`
	Mode        string           `json:"mode"`
	Owner       localstate.Actor `json:"owner"`
	Lifetime    time.Duration    `json:"lifetime"`
	Credentials Credentials      `json:"credentials"`
}
type IdentityProof struct {
	Version  string               `json:"version"`
	Identity plan.FixtureIdentity `json:"identity"`
	Nonce    string               `json:"nonce"`
	MAC      string               `json:"mac"`
}

type controlProof struct {
	Domain     string `json:"domain"`
	FixtureID  string `json:"fixtureID"`
	Path       string `json:"path"`
	Nonce      string `json:"nonce"`
	BodyDigest string `json:"bodyDigest"`
}
type controlResponse struct {
	Status int             `json:"status"`
	Nonce  string          `json:"nonce"`
	Body   json.RawMessage `json:"body"`
	MAC    string          `json:"mac"`
}

func requestProof(id, path, nonce string, data []byte) controlProof {
	return controlProof{"themis.control/v2", id, path, nonce, fmt.Sprintf("sha256:%x", sha256.Sum256(data))}
}

type AuthorizeRequest struct {
	Plan           json.RawMessage  `json:"plan"`
	ApprovedDigest string           `json:"approvedDigest"`
	Actor          localstate.Actor `json:"actor"`
}
type ClaimRequest struct {
	Authorization safety.Authorization `json:"authorization"`
	RunID         string               `json:"runID"`
}
type FaultHandle struct {
	RunID           string    `json:"runID"`
	FaultID         string    `json:"faultID"`
	AuthorizationID string    `json:"authorizationID"`
	FixtureID       string    `json:"fixtureID"`
	ProxyID         string    `json:"proxyID"`
	AdapterVersion  string    `json:"adapterVersion"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
type Lifecycle struct {
	Type    string    `json:"type"`
	FaultID string    `json:"faultID"`
	At      time.Time `json:"at"`
}
type Status struct {
	Identity    plan.FixtureIdentity `json:"identity"`
	ActiveFault *FaultHandle         `json:"activeFault,omitempty"`
	ApplyCount  int                  `json:"applyCount"`
	Events      []Lifecycle          `json:"events"`
	Claim       *ClaimStatus         `json:"claim,omitempty"`
}

type ClaimStatus struct {
	RunID       string   `json:"runID"`
	Quiesced    bool     `json:"quiesced"`
	Interrupted bool     `json:"interrupted"`
	Receipt     *Receipt `json:"receipt,omitempty"`
}
type QuiesceRequest struct {
	Handle FaultHandle `json:"handle"`
	Reason string      `json:"reason"`
}
type ApplyRequest struct {
	Handle FaultHandle `json:"handle"`
}
type Receipt struct {
	Handle         FaultHandle `json:"handle"`
	AppliedAt      time.Time   `json:"appliedAt"`
	FaultExpiresAt time.Time   `json:"faultExpiresAt"`
	AlreadyApplied bool        `json:"alreadyApplied"`
}
type DataResponse struct {
	FixtureID    string `json:"fixtureID"`
	ServiceID    string `json:"serviceID"`
	ProxyID      string `json:"proxyID,omitempty"`
	RequestID    string `json:"requestID"`
	DependencyID string `json:"dependencyID,omitempty"`
	Kind         string `json:"kind"`
	HTTPStatus   int    `json:"httpStatus"`
	Signature    string `json:"signature"`
}

func evidencePrivateKey(token string) ed25519.PrivateKey {
	seed, _ := hex.DecodeString(token)
	return ed25519.NewKeyFromSeed(seed)
}
func signData(token string, body DataResponse) DataResponse {
	body.Signature = ""
	data, _ := json.Marshal(body)
	body.Signature = hex.EncodeToString(ed25519.Sign(evidencePrivateKey(token), data))
	return body
}

// VerifyData authenticates the fixture's response. Client timing itself is not
// signed: offline replay remains a consistency check, not remote attestation.
func VerifyData(body DataResponse, id plan.FixtureIdentity, requestID, kind string) bool {
	sig, err := hex.DecodeString(body.Signature)
	if err != nil {
		return false
	}
	key, err := hex.DecodeString(id.EvidenceKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	body.Signature = ""
	data, _ := json.Marshal(body)
	if !ed25519.Verify(key, data, sig) || body.FixtureID != id.InstanceID || body.ServiceID != id.ServiceID || body.RequestID != requestID {
		return false
	}
	switch kind {
	case "direct":
		return body.Kind == "dependency" && body.ProxyID == "" && body.DependencyID == ""
	case "proxy":
		return body.Kind == "dependency" && body.ProxyID == id.ProxyID && body.DependencyID == ""
	case "application":
		return body.Kind == "application" && body.ProxyID == "" && body.DependencyID == requestID
	default:
		return false
	}
}

func mac(token string, value any) string {
	data, _ := json.Marshal(value)
	h := hmac.New(sha256.New, []byte(token))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
func validMAC(token string, value any, signature string) bool {
	a, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	b, _ := hex.DecodeString(mac(token, value))
	return hmac.Equal(a, b)
}
