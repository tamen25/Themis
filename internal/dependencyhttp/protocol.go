// Package dependencyhttp implements only the disposable native HTTP dependency path.
package dependencyhttp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

const (
	Version        = "themis.native-http/v1alpha1"
	PlanVersion    = "themis.native-http-plan/v1alpha1"
	BindingVersion = "themis.native-http-installation/v1alpha1"
	GrantVersion   = "themis.native-http-grant/v1alpha1"
	CommandVersion = "themis.native-http-command/v1alpha1"
	MaxDelayMS     = 200
	MaxLifetimeMS  = 2000
	RequestMS      = 750
	MaxBody        = 64 << 10
)

var ErrDenied = errors.New("native dependency authority or identity denied")
var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var namespace = regexp.MustCompile(`^themis-dep-[a-f0-9]{12}$`)
var name = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var image = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]{0,240}@sha256:[a-f0-9]{64}$`)

func ID() string { return localstate.RandomID() }
func JSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func Hash(v any) string { s := sha256.Sum256(JSON(v)); return "sha256:" + hex.EncodeToString(s[:]) }
func NewKey() (string, string, error) {
	p, k, e := ed25519.GenerateKey(rand.Reader)
	return hex.EncodeToString(p), hex.EncodeToString(k), e
}
func Public(k string) string {
	b, e := hex.DecodeString(k)
	if e != nil || len(b) != 64 {
		return ""
	}
	return hex.EncodeToString(b[32:])
}
func Sign(domain string, v any, key string) string {
	b, e := hex.DecodeString(key)
	if e != nil || len(b) != 64 {
		return ""
	}
	return hex.EncodeToString(ed25519.Sign(b, append([]byte(domain+"\n"), JSON(v)...)))
}
func Verify(domain string, v any, sig, key string) bool {
	p, e := hex.DecodeString(key)
	s, f := hex.DecodeString(sig)
	return e == nil && f == nil && len(p) == 32 && len(s) == 64 && ed25519.Verify(p, append([]byte(domain+"\n"), JSON(v)...), s)
}
func Decode(b []byte, v any) error {
	if e := localstate.Unmarshal(b, v); e != nil {
		return e
	}
	// Case-insensitive struct matching and explicit nulls are not protocol aliases.
	if !bytes.Equal(bytes.TrimSpace(b), JSON(v)) {
		return errors.New("noncanonical native dependency JSON")
	}
	return nil
}

type Process struct {
	Version      string `json:"version"`
	Role         string `json:"role"`
	ClusterUID   string `json:"clusterUID"`
	NamespaceUID string `json:"namespaceUID"`
	PodUID       string `json:"podUID"`
	Boot         string `json:"boot"`
	Key          string `json:"key"`
}

func (p Process) Valid(role string) bool {
	return p.Version == Version && p.Role == role && uuid.MatchString(p.ClusterUID) && uuid.MatchString(p.NamespaceUID) && uuid.MatchString(p.PodUID) && hexID.MatchString(p.Boot) && hexID.MatchString(p.Key)
}

type Workload struct {
	Name          string  `json:"name"`
	DeploymentUID string  `json:"deploymentUID"`
	Generation    int64   `json:"generation"`
	ReplicaSet    string  `json:"replicaSet"`
	ReplicaSetUID string  `json:"replicaSetUID"`
	Pod           string  `json:"pod"`
	ContainerID   string  `json:"containerID"`
	Image         string  `json:"image"`
	ImageID       string  `json:"imageID"`
	SpecDigest    string  `json:"specDigest"`
	Process       Process `json:"process"`
}

func (w Workload) Valid(role string) bool {
	return w.Name == "native-"+role && uuid.MatchString(w.DeploymentUID) && w.Generation > 0 && name.MatchString(w.ReplicaSet) && uuid.MatchString(w.ReplicaSetUID) && name.MatchString(w.Pod) && strings.HasPrefix(w.ContainerID, "containerd://") && hexID.MatchString(strings.TrimPrefix(w.ContainerID, "containerd://")) && image.MatchString(w.Image) && image.MatchString(w.ImageID) && strings.HasPrefix(w.SpecDigest, "sha256:") && hexID.MatchString(strings.TrimPrefix(w.SpecDigest, "sha256:")) && w.Process.Valid(role)
}

type Target struct {
	Namespace     string   `json:"namespace"`
	Application   Workload `json:"application"`
	Proxy         Workload `json:"proxy"`
	Dependency    Workload `json:"dependency"`
	ApplicationIP string   `json:"applicationIP"`
	DependencyIP  string   `json:"dependencyIP"`
}

func PrivateIP(s string) bool {
	p := net.ParseIP(s)
	return p != nil && p.To4() != nil && p.IsPrivate() && p.String() == s
}
func (t Target) Valid() bool {
	if !namespace.MatchString(t.Namespace) || !t.Application.Valid("application") || !t.Proxy.Valid("proxy") || !t.Dependency.Valid("dependency") || !PrivateIP(t.ApplicationIP) || !PrivateIP(t.DependencyIP) {
		return false
	}
	seen := map[string]bool{}
	for _, w := range []Workload{t.Application, t.Proxy, t.Dependency} {
		p := w.Process
		if p.ClusterUID != t.Proxy.Process.ClusterUID || p.NamespaceUID != t.Proxy.Process.NamespaceUID || seen[p.PodUID] || seen[p.Key] {
			return false
		}
		seen[p.PodUID] = true
		seen[p.Key] = true
	}
	return true
}

type Binding struct {
	Version      string `json:"version"`
	Target       Target `json:"target"`
	Actor        string `json:"actor"`
	ActorUID     string `json:"actorUID"`
	ApproverKey  string `json:"approverKey"`
	InstallerKey string `json:"installerKey"`
	Signature    string `json:"signature"`
}

func (b Binding) Valid() bool {
	s := b.Signature
	b.Signature = ""
	if b.Version != BindingVersion || !b.Target.Valid() || b.Actor != "system:serviceaccount:"+b.Target.Namespace+":native-runner" || !uuid.MatchString(b.ActorUID) || !hexID.MatchString(b.ApproverKey) || !hexID.MatchString(b.InstallerKey) || b.ApproverKey == b.InstallerKey {
		return false
	}
	for _, w := range []Workload{b.Target.Application, b.Target.Proxy, b.Target.Dependency} {
		if w.Process.Key == b.ApproverKey || w.Process.Key == b.InstallerKey {
			return false
		}
	}
	return Verify(BindingVersion, b, s, b.InstallerKey)
}

type Plan struct {
	Version          string  `json:"version"`
	Run              string  `json:"run"`
	Binding          Binding `json:"binding"`
	DelayMS          int     `json:"delayMS"`
	LifetimeMS       int     `json:"lifetimeMS"`
	RequestMS        int     `json:"requestMS"`
	MaxApplicationMS int     `json:"maxApplicationMS"`
	Scenario         string  `json:"scenario"`
}

func (p Plan) Valid() bool {
	return p.Version == PlanVersion && hexID.MatchString(p.Run) && p.Binding.Valid() && p.DelayMS >= 100 && p.DelayMS <= MaxDelayMS && p.LifetimeMS >= 1000 && p.LifetimeMS <= MaxLifetimeMS && p.RequestMS == RequestMS && p.MaxApplicationMS >= 20 && p.MaxApplicationMS <= RequestMS && (p.Scenario == "delay" || p.Scenario == "no-effect" || p.Scenario == "cleanup-unconfirmed")
}
func (p Plan) Digest() string { return Hash(p) }

type Grant struct {
	Version       string    `json:"version"`
	Plan          Plan      `json:"plan"`
	Digest        string    `json:"digest"`
	Invocation    string    `json:"invocation"`
	ApplyKey      string    `json:"applyKey"`
	CleanupKey    string    `json:"cleanupKey"`
	Issued        time.Time `json:"issued"`
	ApplyBefore   time.Time `json:"applyBefore"`
	CleanupBefore time.Time `json:"cleanupBefore"`
	Signature     string    `json:"signature"`
}
type Authorization struct {
	Grant          Grant  `json:"grant"`
	ApplyPrivate   string `json:"applyPrivate"`
	CleanupPrivate string `json:"cleanupPrivate"`
}

func Approve(p Plan, digest, key string, now time.Time) (Authorization, error) {
	if !p.Valid() || p.Digest() != digest || Public(key) != p.Binding.ApproverKey {
		return Authorization{}, ErrDenied
	}
	a, ak, e := NewKey()
	if e != nil {
		return Authorization{}, e
	}
	c, ck, e := NewKey()
	if e != nil {
		return Authorization{}, e
	}
	g := Grant{Version: GrantVersion, Plan: p, Digest: digest, Invocation: ID(), ApplyKey: a, CleanupKey: c, Issued: now.UTC(), ApplyBefore: now.Add(20 * time.Second).UTC(), CleanupBefore: now.Add(5 * time.Minute).UTC()}
	g.Signature = Sign(GrantVersion, g, key)
	return Authorization{g, ak, ck}, nil
}
func (g Grant) Valid(now time.Time, apply bool) bool {
	sig := g.Signature
	g.Signature = ""
	if g.Version != GrantVersion || !g.Plan.Valid() || g.Digest != g.Plan.Digest() || !hexID.MatchString(g.Invocation) || !hexID.MatchString(g.ApplyKey) || !hexID.MatchString(g.CleanupKey) || g.ApplyKey == g.CleanupKey || now.Before(g.Issued) || g.ApplyBefore.Sub(g.Issued) != 20*time.Second || g.CleanupBefore.Sub(g.Issued) != 5*time.Minute {
		return false
	}
	for _, k := range []string{g.Plan.Binding.ApproverKey, g.Plan.Binding.InstallerKey, g.Plan.Binding.Target.Proxy.Process.Key, g.Plan.Binding.Target.Application.Process.Key, g.Plan.Binding.Target.Dependency.Process.Key} {
		if k == g.ApplyKey || k == g.CleanupKey {
			return false
		}
	}
	deadline := g.CleanupBefore
	if apply {
		deadline = g.ApplyBefore
	}
	return now.Before(deadline) && Verify(GrantVersion, g, sig, g.Plan.Binding.ApproverKey)
}

type Command struct {
	Version   string    `json:"version"`
	Action    string    `json:"action"`
	Grant     Grant     `json:"grant"`
	Nonce     string    `json:"nonce"`
	At        time.Time `json:"at"`
	Signature string    `json:"signature"`
}

func NewCommand(action string, a Authorization, now time.Time) Command {
	c := Command{Version: CommandVersion, Action: action, Grant: a.Grant, Nonce: ID(), At: now.UTC()}
	k := a.CleanupPrivate
	if action == "apply" {
		k = a.ApplyPrivate
	}
	c.Signature = Sign(CommandVersion, c, k)
	return c
}

type State struct {
	Invocation string `json:"invocation"`
	Applied    bool   `json:"applied"`
	ApplyCount int    `json:"applyCount"`
	Active     bool   `json:"active"`
	Fenced     bool   `json:"fenced"`
	StartedNS  int64  `json:"startedNS"`
	DeadlineNS int64  `json:"deadlineNS"`
	Reason     string `json:"reason"`
}
type Reply struct {
	Version    string  `json:"version"`
	Identity   Process `json:"identity"`
	Nonce      string  `json:"nonce"`
	Kind       string  `json:"kind"`
	Code       int     `json:"code"`
	State      State   `json:"state"`
	PlanDigest string  `json:"planDigest"`
	Action     string  `json:"action"`
	Value      string  `json:"value"`
	HoldNS     int64   `json:"holdNS"`
	Dependency *Reply  `json:"dependency,omitempty"`
	Proxy      *Reply  `json:"proxy,omitempty"`
	Signature  string  `json:"signature"`
}

func (r Reply) Verified(identity Process, nonce, kind string) bool {
	s := r.Signature
	r.Signature = ""
	return r.Version == Version && r.Identity == identity && r.Nonce == nonce && hexID.MatchString(nonce) && r.Kind == kind && Verify(Version, r, s, identity.Key)
}
