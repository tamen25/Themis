// Package v1alpha1 defines the experimental Kubernetes dry-run projection.
// It is independent of the published local contract and journal formats.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/tamen25/themis/internal/result"
)

const Group = "verification.themis.dev"

var RunGVK = schema.GroupVersionKind{Group: Group, Version: "v1alpha1", Kind: "VerificationRun"}

type ContractSnapshot struct {
	SchemaVersion string `json:"schemaVersion"`
	Name          string `json:"name"`
	Assertion     string `json:"assertion"`
	MinReplicas   int32  `json:"minReplicas"`
}

type TargetReference struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
	Generation int64     `json:"generation"`
}

type RunSpec struct {
	SchemaVersion    string           `json:"schemaVersion"`
	ExecutionProfile string           `json:"executionProfile"`
	Contract         ContractSnapshot `json:"contract"`
	Target           TargetReference  `json:"target"`
}

type ImageIdentity struct {
	Container string `json:"container"`
	Image     string `json:"image"`
	Init      bool   `json:"init"`
}

type TargetIdentity struct {
	Reference          TargetReference `json:"reference"`
	ClusterUID         types.UID       `json:"clusterUID"`
	NamespaceUID       types.UID       `json:"namespaceUID"`
	ObservedGeneration int64           `json:"observedGeneration"`
	TemplateDigest     string          `json:"templateDigest"`
	OwnershipDigest    string          `json:"ownershipDigest"`
	Images             []ImageIdentity `json:"images"`
}

type PlanDocument struct {
	SchemaVersion    string           `json:"schemaVersion"`
	PlannerVersion   string           `json:"plannerVersion"`
	PolicyVersion    string           `json:"policyVersion"`
	RunUID           types.UID        `json:"runUID"`
	RunGeneration    int64            `json:"runGeneration"`
	SpecDigest       string           `json:"specDigest"`
	ContractDigest   string           `json:"contractDigest"`
	Contract         ContractSnapshot `json:"contract"`
	Target           TargetIdentity   `json:"target"`
	ExecutionProfile string           `json:"executionProfile"`
	ExecutionAllowed bool             `json:"executionAllowed"`
}

type PlanPreview struct {
	Digest string       `json:"digest"`
	Plan   PlanDocument `json:"plan"`
}

type RunStatus struct {
	ObservedGeneration int64              `json:"observedGeneration"`
	Phase              string             `json:"phase"`
	Reason             string             `json:"reason"`
	Message            string             `json:"message"`
	Verdict            result.Verdict     `json:"verdict"`
	ExecutionAllowed   bool               `json:"executionAllowed"`
	PlanValid          bool               `json:"planValid"`
	Invalidated        bool               `json:"invalidated"`
	PlanDigest         string             `json:"planDigest,omitempty"`
	CandidateDigest    string             `json:"candidatePlanDigest,omitempty"`
	Preview            *PlanPreview       `json:"preview,omitempty"`
	Conditions         []metav1.Condition `json:"conditions"`
	// These classify the status claim, not measured Kubernetes reliability.
	Provenance string `json:"provenance"`
}
