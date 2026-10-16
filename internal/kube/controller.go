package kube

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func RunObject() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(api.RunGVK)
	return u
}

// Reader bypasses the informer cache for decisions. The status update carries
// the resourceVersion read with the spec, rejecting concurrent spec changes.
type Reconciler struct {
	Client client.Client
	Reader client.Reader
	Policy Policy
}

func ReadStatus(u *unstructured.Unstructured) api.RunStatus {
	var s api.RunStatus
	data, _, _ := unstructured.NestedMap(u.Object, "status")
	_ = runtime.DefaultUnstructuredConverter.FromUnstructured(data, &s)
	return s
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Namespace != Namespace {
		return ctrl.Result{}, nil // never read or mutate another namespace
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u := RunObject()
	if err := r.Reader.Get(ctx, req.NamespacedName, u); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !u.GetDeletionTimestamp().IsZero() {
		return ctrl.Result{}, nil // no finalizer or owned execution resources exist
	}
	prior := ReadStatus(u)
	s := api.RunStatus{ObservedGeneration: u.GetGeneration(), Phase: "DENIED", Reason: "InvalidSpecification", Message: "unsupported or invalid run specification", Verdict: result.NotRun, Conditions: append([]metav1.Condition{}, prior.Conditions...), Preview: prior.Preview, Provenance: "KUBERNETES_API_PREVIEW_ONLY_NO_EXECUTION_EVIDENCE"}
	s.Invalidated = prior.Invalidated
	knownEnvelope := true
	for key := range u.Object {
		if key != "apiVersion" && key != "kind" && key != "metadata" && key != "spec" && key != "status" {
			knownEnvelope = false
		}
	}
	data, _ := json.Marshal(u.Object["spec"])
	spec, err := DecodeSpec(data)
	if err == nil && knownEnvelope {
		if code := r.Policy.Validate(u.GetNamespace(), spec); code != "" {
			s.Reason = code
			s.Message = "trusted dry-run policy denied the request"
		} else {
			r.resolve(ctx, u, spec, &s)
		}
	}
	if s.Invalidated && s.Phase == "PLANNED" {
		s.CandidateDigest = s.PlanDigest
		s.Phase, s.Reason, s.Message, s.Verdict = "INVALIDATED", "PlanPreviouslyInvalidated", "a previously invalidated run cannot be readmitted; create a new VerificationRun", result.Inconclusive
		s.PlanValid, s.PlanDigest = false, ""
	}
	for _, condition := range []metav1.Condition{
		{Type: "Admitted", Status: truth(s.Phase == "PLANNED"), Reason: s.Reason, Message: s.Message, ObservedGeneration: s.ObservedGeneration},
		{Type: "PlanReady", Status: truth(s.PlanValid), Reason: s.Reason, Message: s.Message, ObservedGeneration: s.ObservedGeneration},
		{Type: "TargetResolved", Status: truth(s.PlanValid), Reason: s.Reason, Message: s.Message, ObservedGeneration: s.ObservedGeneration},
		{Type: "ExecutionAllowed", Status: metav1.ConditionFalse, Reason: "DryRunOnly", Message: "T2.0 has no Kubernetes execution or fault adapter", ObservedGeneration: s.ObservedGeneration},
	} {
		meta.SetStatusCondition(&s.Conditions, condition)
	}
	if !reflect.DeepEqual(prior, s) {
		status, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&s)
		if err != nil {
			return ctrl.Result{}, err
		}
		u.Object["status"] = status
		if err := r.Client.Status().Update(ctx, u); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func truth(value bool) metav1.ConditionStatus {
	if value {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func (r *Reconciler) resolve(ctx context.Context, u *unstructured.Unstructured, spec api.RunSpec, s *api.RunStatus) {
	s.Phase, s.Reason, s.Message, s.Verdict = "WAITING", "TargetUnavailable", "target or trusted environment could not be resolved", result.Inconclusive
	cluster, namespace, target := &corev1.Namespace{}, &corev1.Namespace{}, &appsv1.Deployment{}
	for _, read := range []struct {
		key types.NamespacedName
		obj client.Object
	}{{types.NamespacedName{Name: "kube-system"}, cluster}, {types.NamespacedName{Name: Namespace}, namespace}, {types.NamespacedName{Namespace: Namespace, Name: spec.Target.Name}, target}} {
		if err := r.Reader.Get(ctx, read.key, read.obj); err != nil {
			if apierrors.IsNotFound(err) {
				s.Reason, s.Message = "TargetNotFound", "requested target or pinned namespace is absent"
			} else if apierrors.IsForbidden(err) {
				s.Phase, s.Reason, s.Message = "ERROR", "ReadForbidden", "controller identity lacks the required read permission"
			} else {
				s.Phase, s.Reason, s.Message = "ERROR", "APIReadFailed", "Kubernetes API read failed; no execution attempted"
			}
			return
		}
	}
	p, code := r.Policy.Compile(u.GetUID(), u.GetGeneration(), spec, cluster, namespace, target)
	if code != "" {
		s.Reason, s.Message = code, "target or environment no longer satisfies the frozen request"
		if code != "TargetGenerationUnobserved" {
			s.Phase = "DENIED"
		}
		if s.Preview != nil {
			s.Phase = "INVALIDATED"
			s.Invalidated = true
		}
		return
	}
	preview := p.Snapshot()
	if s.Preview != nil && s.Preview.Digest != preview.Digest {
		s.Invalidated = true
		s.Phase, s.Reason, s.Message, s.CandidateDigest = "INVALIDATED", "PlanInputsChanged", "prior preview retained; changed spec or target requires a new VerificationRun", preview.Digest
		return
	}
	s.Phase, s.Reason, s.Message, s.Verdict = "PLANNED", "DryRunPlanned", "deterministic preview only; no reliability assertion was executed", result.NotRun
	s.PlanValid, s.PlanDigest, s.Preview = true, preview.Digest, &preview
}
