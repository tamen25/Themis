// Package kubefault is the bounded synthetic HTTP fixture protocol. It has no
// Kubernetes client or local OS authorization dependency.
package kubefault

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	strictjson "sigs.k8s.io/json"
)

const Version = "themis.kubernetes-fixture/v1alpha1"
const PlanVersion = "themis.kubernetes-experiment-plan/v1alpha1"
const PolicyVersion = "themis.owned-kind/t2.1-v1"
const GrantVersion = "themis.kubernetes-authorization/v1alpha1"
const OperatorName = "system:serviceaccount:themis-test:themis-runner"

var ErrDenied = errors.New("owned Kind experiment admission denied")
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var hashID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var objectName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
var imageReference = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)
var runningImage = regexp.MustCompile(`^([^\s]+@|[^\s]+://)?sha256:[a-f0-9]{64}$`)

type Actor struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type Identity struct {
	Version      string `json:"version"`
	ClusterUID   string `json:"clusterUID"`
	NamespaceUID string `json:"namespaceUID"`
	PodName      string `json:"podName"`
	PodUID       string `json:"podUID"`
	InstanceID   string `json:"instanceID"`
	ProxyID      string `json:"proxyID"`
	EvidenceKey  string `json:"evidenceKey"`
}

type Target struct {
	Namespace            string   `json:"namespace"`
	Fixture              Identity `json:"fixture"`
	DeploymentName       string   `json:"deploymentName"`
	DeploymentUID        string   `json:"deploymentUID"`
	DeploymentGeneration int64    `json:"deploymentGeneration"`
	TemplateDigest       string   `json:"templateDigest"`
	ReplicaSetName       string   `json:"replicaSetName"`
	ReplicaSetUID        string   `json:"replicaSetUID"`
	PodSpecDigest        string   `json:"podSpecDigest"`
	ContainerID          string   `json:"containerID"`
	Image                string   `json:"image"`
	ImageID              string   `json:"imageID"`
}

type Contract struct {
	Version          string `json:"version"`
	Name             string `json:"name"`
	Samples          int    `json:"samples"`
	MinConfirmed     int    `json:"minConfirmed"`
	MaxErrorFraction string `json:"maximumErrorFraction"`
}

type Fault struct {
	Type       string `json:"type"`
	DelayMS    int    `json:"delayMS"`
	DurationMS int    `json:"durationMS"`
}

type Plan struct {
	Version       string   `json:"version"`
	Policy        string   `json:"policy"`
	RunName       string   `json:"runName"`
	RunUID        string   `json:"runUID"`
	RunGeneration int64    `json:"runGeneration"`
	PreviewDigest string   `json:"previewDigest"`
	Operator      Actor    `json:"operator"`
	Target        Target   `json:"target"`
	Contract      Contract `json:"contract"`
	Fault         Fault    `json:"fault"`
	Scenario      string   `json:"scenario"`
}

func (p Plan) Digest() string { return Digest(PlanVersion, p) }

func (p Plan) Validate() error {
	i := p.Target.Fixture
	if p.Version != PlanVersion || p.Policy != PolicyVersion || p.Operator.Name != OperatorName || !uuid.MatchString(p.Operator.UID) || !uuid.MatchString(p.RunUID) || p.RunGeneration < 1 || !hashID.MatchString(p.PreviewDigest) || !validName(p.RunName) {
		return ErrDenied
	}
	if i.Version != Version || !uuid.MatchString(i.ClusterUID) || !uuid.MatchString(i.NamespaceUID) || i.ClusterUID == i.NamespaceUID || !uuid.MatchString(i.PodUID) || !validName(i.PodName) || !hexID.MatchString(i.InstanceID) || !hexID.MatchString(i.ProxyID) || !validPublic(i.EvidenceKey) {
		return ErrDenied
	}
	t := p.Target
	if t.Namespace != "themis-test" || t.DeploymentName != "latency-fixture" || !uuid.MatchString(t.DeploymentUID) || t.DeploymentGeneration < 1 || !uuid.MatchString(t.ReplicaSetUID) || !validName(t.ReplicaSetName) || !hashID.MatchString(t.TemplateDigest) || !hashID.MatchString(t.PodSpecDigest) || len(t.Image) > 512 || len(t.ImageID) > 512 || len(t.ContainerID) > 256 || t.ContainerID == "" {
		return ErrDenied
	}
	if !imageReference.MatchString(t.Image) || !runningImage.MatchString(t.ImageID) {
		return ErrDenied
	}
	if p.Contract.Version != "themis.kubernetes-experiment-contract/v1alpha1" || !validName(p.Contract.Name) || p.Contract.Samples != 3 || p.Contract.MinConfirmed != 3 || p.Contract.MaxErrorFraction != "0" || p.Fault.Type != "http.response-latency" || p.Fault.DelayMS < 150 || p.Fault.DelayMS > 300 || p.Fault.DurationMS < 1500 || p.Fault.DurationMS > 3000 {
		return ErrDenied
	}
	switch p.Scenario {
	case "healthy", "buggy", "noop", "cleanup-denied":
		return nil
	default:
		return ErrDenied
	}
}

func validName(v string) bool { return len(v) <= 253 && objectName.MatchString(v) }
func validPublic(v string) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == ed25519.PublicKeySize
}

type Grant struct {
	Version       string    `json:"version"`
	InvocationID  string    `json:"invocationID"`
	Plan          Plan      `json:"plan"`
	PlanDigest    string    `json:"planDigest"`
	InvocationKey string    `json:"invocationKey"`
	CleanupKey    string    `json:"cleanupKey"`
	IssuedAt      time.Time `json:"issuedAt"`
	ApplyBefore   time.Time `json:"applyBefore"`
	CleanupBefore time.Time `json:"cleanupBefore"`
	Signature     string    `json:"signature"`
}

// Authorization is private capability state. It never belongs in public logs.
type Authorization struct {
	Grant         Grant  `json:"grant"`
	InvocationKey string `json:"invocationPrivateKey"`
	CleanupKey    string `json:"cleanupPrivateKey"`
}

// CheckKeys rejects damaged local capabilities before a runner can create an
// intent or apply a fault that it lacks the separate key to clean up.
func (a Authorization) CheckKeys() error {
	for _, pair := range [][2]string{{a.InvocationKey, a.Grant.InvocationKey}, {a.CleanupKey, a.Grant.CleanupKey}} {
		key, err := hex.DecodeString(pair[0])
		if err != nil || len(key) != ed25519.PrivateKeySize {
			return ErrDenied
		}
		canonical := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if hex.EncodeToString(canonical) != pair[0] || hex.EncodeToString(canonical[ed25519.SeedSize:]) != pair[1] {
			return ErrDenied
		}
	}
	return nil
}

func Approve(p Plan, digest string, signer ed25519.PrivateKey, now time.Time) (Authorization, error) {
	if p.Validate() != nil || digest != p.Digest() || len(signer) != ed25519.PrivateKeySize {
		return Authorization{}, ErrDenied
	}
	runPublic, runKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Authorization{}, err
	}
	cleanupPublic, cleanupKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Authorization{}, err
	}
	g := Grant{Version: GrantVersion, InvocationID: RandomID(), Plan: p, PlanDigest: digest, InvocationKey: hex.EncodeToString(runPublic), CleanupKey: hex.EncodeToString(cleanupPublic), IssuedAt: now.UTC(), ApplyBefore: now.Add(20 * time.Second).UTC(), CleanupBefore: now.Add(90 * time.Second).UTC()}
	g.Signature = Sign(GrantVersion, g, signer)
	return Authorization{g, hex.EncodeToString(runKey), hex.EncodeToString(cleanupKey)}, nil
}

func VerifyGrant(g Grant, public string, identity Identity, actor Actor, now time.Time, apply bool) bool {
	sig := g.Signature
	g.Signature = ""
	if !Verify(GrantVersion, g, sig, public) || g.Version != GrantVersion || !hexID.MatchString(g.InvocationID) || g.Plan.Validate() != nil || g.PlanDigest != g.Plan.Digest() || g.Plan.Target.Fixture != identity || g.Plan.Operator != actor || !validPublic(g.InvocationKey) || !validPublic(g.CleanupKey) || g.InvocationKey == g.CleanupKey || g.IssuedAt.After(now) || g.ApplyBefore.Sub(g.IssuedAt) != 20*time.Second || g.CleanupBefore.Sub(g.IssuedAt) != 90*time.Second || !now.Before(g.CleanupBefore) {
		return false
	}
	return !apply || now.Before(g.ApplyBefore)
}

type Command struct {
	Grant     Grant     `json:"grant"`
	Action    string    `json:"action"`
	Nonce     string    `json:"nonce"`
	At        time.Time `json:"at"`
	Signature string    `json:"signature"`
}

func NewCommand(a Authorization, action string) (Command, error) {
	key := a.CleanupKey
	if action == "apply" {
		key = a.InvocationKey
	}
	private, err := hex.DecodeString(key)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return Command{}, ErrDenied
	}
	c := Command{Grant: a.Grant, Action: action, Nonce: RandomID(), At: time.Now().UTC()}
	c.Signature = Sign("themis.kubernetes-command/v1alpha1", c, private)
	return c, nil
}

type Status struct {
	InvocationID string        `json:"invocationID"`
	Applied      bool          `json:"applied"`
	Active       bool          `json:"active"`
	ApplyCount   int           `json:"applyCount"`
	AppliedAt    time.Time     `json:"appliedAt"`
	ExpiresAt    time.Time     `json:"expiresAt"`
	Reason       string        `json:"reason"`
	Proof        *ControlProof `json:"proof,omitempty"`
}

type ControlProof struct {
	Nonce     string `json:"nonce"`
	HTTPCode  int    `json:"httpCode"`
	Error     string `json:"error"`
	Signature string `json:"signature"`
}

func VerifyStatus(s Status, id Identity) bool {
	if s.Proof == nil {
		return false
	}
	proof := *s.Proof
	s.Proof = nil
	r := Reply{Identity: id, Nonce: proof.Nonce, HTTPCode: proof.HTTPCode, Status: s, Error: proof.Error}
	return proof.HTTPCode == 200 && proof.Error == "" && Verify("themis.kubernetes-reply/v1alpha1", r, proof.Signature, id.EvidenceKey)
}

type Reply struct {
	Identity  Identity `json:"identity"`
	Nonce     string   `json:"nonce"`
	HTTPCode  int      `json:"httpCode"`
	Status    Status   `json:"status"`
	Error     string   `json:"error"`
	Signature string   `json:"signature"`
}

type Data struct {
	Identity     Identity `json:"identity"`
	RequestID    string   `json:"requestID"`
	Kind         string   `json:"kind"`
	InvocationID string   `json:"invocationID"`
	HTTPCode     int      `json:"httpCode"`
	Degraded     bool     `json:"degraded"`
	ProxyDelayNS int64    `json:"proxyDelayNS,omitempty"`
	Signature    string   `json:"signature"`
}

func VerifyData(d Data, id Identity, requestID, kind string, code int) bool {
	sig := d.Signature
	d.Signature = ""
	return d.Identity == id && d.RequestID == requestID && d.Kind == kind && d.HTTPCode == code && Verify("themis.kubernetes-data/v1alpha1", d, sig, id.EvidenceKey)
}

func Digest(domain string, value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(append([]byte(domain+"\n"), b...))
	return "sha256:" + hex.EncodeToString(h[:])
}
func Sign(domain string, value any, key ed25519.PrivateKey) string {
	b, _ := json.Marshal(value)
	return hex.EncodeToString(ed25519.Sign(key, append([]byte(domain+"\n"), b...)))
}
func Verify(domain string, value any, signature, public string) bool {
	s, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	k, err := hex.DecodeString(public)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return false
	}
	b, err := json.Marshal(value)
	return err == nil && ed25519.Verify(k, append([]byte(domain+"\n"), b...), s)
}
func RandomID() string {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("OS entropy unavailable")
	}
	return hex.EncodeToString(id[:])
}
func Decode(data []byte, value any) error {
	if len(data) > 65536 {
		return errors.New("fixture artifact exceeds 64KiB")
	}
	strict, err := strictjson.UnmarshalStrict(data, value)
	if err != nil || len(strict) != 0 {
		return errors.New("invalid or unsupported fixture artifact")
	}
	return nil
}
