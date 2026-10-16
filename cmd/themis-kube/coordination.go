package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/result"
)

func runCoordination(parent context.Context, args []string, out, diagnostics io.Writer) int {
	usage := func() {
		fmt.Fprintln(diagnostics, "usage: themis-kube coordinate preview | prepare | approve | start | status | cancel | reconcile | verify")
	}
	if len(args) == 0 {
		usage()
		return 4
	}
	if args[0] == "--help" || args[0] == "-h" {
		usage()
		return 0
	}
	command := args[0]
	f := flag.NewFlagSet("themis-kube coordinate "+command, flag.ContinueOnError)
	f.SetOutput(diagnostics)
	state := f.String("state", ".themis/kind-t21", "explicit owned private setup")
	var directory, runName, scenario, digest *string
	switch command {
	case "preview", "prepare":
		runName = f.String("run", "latency-request", "exact VerificationRun")
		scenario = f.String("scenario", "healthy", "explicit synthetic scenario")
		if command == "prepare" {
			directory = f.String("directory", "", "new private coordination directory")
		}
	case "approve", "start", "status", "cancel", "reconcile", "verify":
		directory = f.String("directory", "", "original private coordination directory")
		if command == "approve" {
			digest = f.String("approve-digest", "", "exact independently resolved execution-plan digest")
		}
	default:
		usage()
		return 4
	}
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 4
	}
	if f.NArg() != 0 || directory != nil && *directory == "" || digest != nil && *digest == "" {
		return 4
	}
	emit := func(value any) int {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if encoder.Encode(value) != nil {
			return 6
		}
		return 0
	}
	failure := func(err error) int {
		if errors.Is(err, kubefault.ErrDenied) {
			fmt.Fprintln(diagnostics, "coordination admission denied; original invocation is not retried")
			return 5
		}
		fmt.Fprintln(diagnostics, "coordination operation failed; inspect protected state and original experiment evidence")
		return 6
	}
	if command == "verify" {
		verified, err := kubeexperiment.VerifyCoordination(*directory)
		if verified.Version != "" {
			if code := emit(verified); code != 0 {
				return code
			}
		}
		if err != nil {
			return failure(err)
		}
		if !verified.BindingsValid {
			return 6
		}
		if verified.CredibleSignedFailure {
			return 2
		}
		return 3
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	var cluster *kubeexperiment.Cluster
	var err error
	if command == "preview" || command == "prepare" {
		cluster, err = kubeexperiment.Open(ctx, *state)
	} else {
		explicit := ""
		f.Visit(func(v *flag.Flag) {
			if v.Name == "state" {
				explicit = *state
			}
		})
		cluster, err = kubeexperiment.OpenCoordination(ctx, *directory, explicit)
	}
	if err != nil {
		if command == "cancel" || command == "reconcile" {
			if code := emit(map[string]any{"version": "themis.kubernetes-coordination-failure/v1alpha1", "executionState": "UNKNOWN", "cleanupDisposition": "CLEANUP_PENDING", "cancellationState": "NOT_ACCEPTED", "problems": []string{"protected coordination inventory unavailable; no identity guessed or mutation attempted"}}); code != 0 {
				return code
			}
			return 7
		}
		return failure(err)
	}
	var record kubeexperiment.CoordinationRecord
	switch command {
	case "preview":
		record, err = cluster.PreviewCoordination(ctx, *runName, *scenario)
	case "prepare":
		record, err = cluster.PrepareCoordination(ctx, *runName, *scenario, *directory)
	case "approve":
		record, err = cluster.ApproveCoordination(ctx, *directory, *digest)
	case "start":
		record, err = cluster.StartCoordination(ctx, *directory)
	case "status":
		record, err = cluster.InspectCoordination(ctx, *directory)
	case "cancel":
		record, err = cluster.CancelCoordination(ctx, *directory)
	case "reconcile":
		record, err = cluster.ReconcileCoordination(ctx, *directory)
	}
	if record.Version != "" {
		if code := emit(record); code != 0 {
			return code
		}
	}
	if err != nil {
		if command == "cancel" || command == "reconcile" || record.LiveResult != nil && record.LiveResult.Execution == result.CleanupPending {
			return 7
		}
		return failure(err)
	}
	if command == "start" {
		if record.LiveResult == nil {
			return 6
		}
		return reportExit(*record.LiveResult)
	}
	if command == "cancel" || command == "reconcile" {
		if record.CleanupDisposition != "CLEANUP_COMPLETE" && record.CleanupDisposition != "NOT_REQUIRED" {
			return 7
		}
	}
	return 0
}
