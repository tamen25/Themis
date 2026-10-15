package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
)

var fixtureName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func Start(ctx context.Context, executable, directory, name, mode string, lifetime time.Duration) (plan.FixtureIdentity, error) {
	if !fixtureName.MatchString(name) {
		return plan.FixtureIdentity{}, errors.New("invalid fixture name")
	}
	if mode != "healthy" && mode != "buggy" && mode != "noop-adapter" && mode != "cleanup-denied" {
		return plan.FixtureIdentity{}, errors.New("unknown fixture demo mode")
	}
	if lifetime < 15*time.Second || lifetime > localpolicy.FixtureTTL {
		return plan.FixtureIdentity{}, errors.New("fixture lifetime must be between 15s and 2m")
	}
	actor, err := localstate.CurrentActor()
	if err != nil {
		return plan.FixtureIdentity{}, err
	}
	dir, err := localstate.CreateDirectory(directory)
	if err != nil {
		return plan.FixtureIdentity{}, err
	}
	credentials := Credentials{localstate.RandomID(), localstate.RandomID()}
	if err := localstate.WriteNew(filepath.Join(dir, "credentials.json"), credentials); err != nil {
		return plan.FixtureIdentity{}, err
	}
	config := WorkerConfig{dir, name, mode, actor, lifetime, credentials}
	data, _ := json.Marshal(config)
	log, err := localstate.OpenNew(filepath.Join(dir, "worker.log"))
	if err != nil {
		return plan.FixtureIdentity{}, err
	}
	defer log.Close()
	command := exec.Command(executable, HiddenCommand)
	configureProcess(command)
	command.Stdin = bytes.NewReader(data)
	command.Stdout = log
	command.Stderr = log
	if err := command.Start(); err != nil {
		return plan.FixtureIdentity{}, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return plan.FixtureIdentity{}, fmt.Errorf("fixture worker stopped before ready: %v", err)
		case <-ctx.Done():
			_ = command.Process.Kill()
			return plan.FixtureIdentity{}, ctx.Err()
		case <-timer.C:
			_ = command.Process.Kill()
			return plan.FixtureIdentity{}, errors.New("fixture startup timed out")
		case <-ticker.C:
			var id plan.FixtureIdentity
			if err := localstate.Read(filepath.Join(dir, "identity.json"), &id); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				_ = command.Process.Kill()
				return plan.FixtureIdentity{}, err
			}
			client, err := Open(dir)
			if err != nil {
				_ = command.Process.Kill()
				return plan.FixtureIdentity{}, err
			}
			defer client.Close()
			actual, err := client.Resolve(ctx)
			if err != nil {
				_ = command.Process.Kill()
				return plan.FixtureIdentity{}, err
			}
			return actual, nil
		}
	}
}
