// Package kube implements the non-destructive Kubernetes projection. It cannot
// invoke the local fixture authority or any fault adapter.
package kube

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	strictjson "sigs.k8s.io/json"
)

const Namespace = "themis-test"
const Profile = "kind-dry-run"
const PolicyVersion = "themis.kubernetes-safety/t2.0-v1"

var uidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)

// Policy is configured by the operator, never by a VerificationRun author.
type Policy struct{ clusterUID, namespaceUID types.UID }

func (p Policy) CheckEnvironment(cluster, namespace *corev1.Namespace) bool {
	return cluster != nil && namespace != nil && p.clusterUID != "" && p.namespaceUID != "" && cluster.Name == "kube-system" && namespace.Name == Namespace && cluster.UID == p.clusterUID && namespace.UID == p.namespaceUID && cluster.DeletionTimestamp.IsZero() && namespace.DeletionTimestamp.IsZero()
}

func NewPolicy(namespace string, clusterUID, namespaceUID types.UID) (Policy, error) {
	if namespace != Namespace || !uidPattern.MatchString(string(clusterUID)) || !uidPattern.MatchString(string(namespaceUID)) || clusterUID == namespaceUID {
		return Policy{}, errors.New("explicit themis-test namespace and distinct cluster/namespace UID pins required")
	}
	return Policy{clusterUID, namespaceUID}, nil
}

func DecodeSpec(data []byte) (api.RunSpec, error) {
	var s api.RunSpec
	if len(data) > 8192 {
		return s, errors.New("run specification exceeds 8KiB")
	}
	strictErrors, err := strictjson.UnmarshalStrict(data, &s)
	if err != nil || len(strictErrors) != 0 {
		return s, errors.New("unsupported or invalid specification fields")
	}
	return s, nil
}

func (p Policy) Validate(namespace string, s api.RunSpec) string {
	if p.clusterUID == "" || p.namespaceUID == "" || namespace != Namespace || s.Target.Namespace != namespace {
		return "NamespaceDenied"
	}
	if s.SchemaVersion != "themis.kubernetes-run/v1alpha1" || s.Contract.SchemaVersion != "themis.kubernetes-contract/v1alpha1" {
		return "UnsupportedSchema"
	}
	if s.ExecutionProfile != Profile || s.Contract.Assertion != "DeploymentAvailable" || s.Contract.MinReplicas != 1 {
		return "UnsupportedOperation"
	}
	if len(validation.IsDNS1123Subdomain(s.Contract.Name)) != 0 || len(s.Contract.Name) > 63 || s.Target.APIVersion != "apps/v1" || s.Target.Kind != "Deployment" || len(validation.IsDNS1123Subdomain(s.Target.Name)) != 0 || !uidPattern.MatchString(string(s.Target.UID)) || s.Target.Generation < 1 {
		return "InvalidTargetOrContract"
	}
	return ""
}

func digest(domain string, value any) string {
	data, _ := json.Marshal(value) // all callers use concrete JSON-safe value types
	return fmt.Sprintf("sha256:%x", sha256.Sum256(append([]byte(domain+"\n"), data...)))
}

// FrozenPlan owns canonical bytes; callers receive independent snapshots.
type FrozenPlan struct {
	data   string
	digest string
}

func (p FrozenPlan) Snapshot() api.PlanPreview {
	var d api.PlanDocument
	_ = json.Unmarshal([]byte(p.data), &d)
	return api.PlanPreview{Digest: p.digest, Plan: d}
}

// Compile is pure: its caller must supply fresh API reads and trusted UID pins.
// A successful preview grants no execution authority.
func (p Policy) Compile(runUID types.UID, generation int64, s api.RunSpec, cluster, namespace *corev1.Namespace, d *appsv1.Deployment) (FrozenPlan, string) {
	if cluster == nil || namespace == nil || d == nil {
		return FrozenPlan{}, "TargetUnavailable"
	}
	if code := p.Validate(namespace.Name, s); code != "" {
		return FrozenPlan{}, code
	}
	if !uidPattern.MatchString(string(runUID)) || generation < 1 || !p.CheckEnvironment(cluster, namespace) {
		return FrozenPlan{}, "EnvironmentIdentityChanged"
	}
	if d.Namespace != s.Target.Namespace || d.Name != s.Target.Name || d.UID != s.Target.UID || d.Generation != s.Target.Generation || !d.DeletionTimestamp.IsZero() {
		return FrozenPlan{}, "TargetIdentityChanged"
	}
	if d.Status.ObservedGeneration != d.Generation {
		return FrozenPlan{}, "TargetGenerationUnobserved"
	}
	t := d.Spec.Template.Spec
	if d.Labels[api.Group+"/synthetic"] != "true" || t.HostNetwork || t.HostPID || t.HostIPC || len(t.EphemeralContainers) != 0 || len(t.Containers) == 0 || len(t.Containers)+len(t.InitContainers) > 4 {
		return FrozenPlan{}, "UnsafeTarget"
	}
	for _, v := range t.Volumes {
		if v.HostPath != nil {
			return FrozenPlan{}, "UnsafeTarget"
		}
	}
	images := []api.ImageIdentity{}
	for i, containers := range [][]corev1.Container{t.Containers, t.InitContainers} {
		for _, c := range containers {
			if len(c.Image) > 512 || !imagePattern.MatchString(c.Image) || c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				return FrozenPlan{}, "UnpinnedOrUnsafeImage"
			}
			images = append(images, api.ImageIdentity{Container: c.Name, Image: c.Image, Init: i == 1})
		}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Container < images[j].Container })
	owners := append([]metav1.OwnerReference{}, d.OwnerReferences...)
	sort.Slice(owners, func(i, j int) bool { return owners[i].UID < owners[j].UID })
	id := api.TargetIdentity{Reference: s.Target, ClusterUID: p.clusterUID, NamespaceUID: p.namespaceUID, ObservedGeneration: d.Status.ObservedGeneration, TemplateDigest: digest("themis.pod-template/v1alpha1", d.Spec.Template), OwnershipDigest: digest("themis.owners/v1alpha1", owners), Images: images}
	doc := api.PlanDocument{SchemaVersion: "themis.kubernetes-plan/v1alpha1", PlannerVersion: "themis.kubernetes-planner/t2.0-v1", PolicyVersion: PolicyVersion, RunUID: runUID, RunGeneration: generation, SpecDigest: digest("themis.kubernetes-spec/v1alpha1", s), ContractDigest: digest("themis.kubernetes-contract/v1alpha1", s.Contract), Contract: s.Contract, Target: id, ExecutionProfile: Profile, ExecutionAllowed: false}
	data, _ := json.Marshal(doc)
	return FrozenPlan{string(data), digest(doc.SchemaVersion, doc)}, ""
}
