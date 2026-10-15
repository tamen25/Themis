// Package localstate protects local control credentials and durable private state.
package localstate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

type Actor struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	Host string `json:"host"`
}

func CurrentActor() (Actor, error) {
	u, err := user.Current()
	if err != nil {
		return Actor{}, err
	}
	host, err := os.Hostname()
	if err != nil {
		return Actor{}, err
	}
	return Actor{u.Uid, u.Username, host}, nil
}
func RandomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("OS entropy unavailable")
	}
	return hex.EncodeToString(b[:])
}

func CreateDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return "", err
	}
	if err := os.Mkdir(abs, 0700); err != nil {
		return "", err
	}
	if err := protect(abs, true); err != nil {
		return "", fmt.Errorf("protect local state: %w", err)
	}
	if err := Check(abs); err != nil {
		return "", err
	}
	if err := SyncDirectory(filepath.Dir(abs)); err != nil {
		return "", err
	}
	return abs, nil
}

func Check(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("local state must not be a symbolic link")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return errors.New("local state must be a regular file or directory")
	}
	return checkPrivate(path, info)
}

// WriteNew never replaces existing state. Its parent must already be private.
func WriteNew(path string, value any) error {
	if err := Check(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	// Publish a complete, synced file without replacing an existing record.
	// Hard-link creation is atomic on the supported local NTFS/ext4 filesystems.
	temporary := filepath.Join(filepath.Dir(path), ".pending-"+RandomID())
	f, err := OpenNew(temporary)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	defer f.Close()
	data = append(data, '\n')
	if n, err := f.Write(data); err != nil {
		return err
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	return SyncDirectory(filepath.Dir(path))
}

// OpenNew creates an owner-only append file and never opens an existing file.
func OpenNew(path string) (*os.File, error) {
	if err := Check(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := protect(path, false); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func Read(path string, value any) error {
	if err := Check(filepath.Dir(path)); err != nil {
		return err
	}
	if err := Check(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	return Unmarshal(data, value)
}

// Unmarshal rejects duplicate/case-conflicting keys, unknown fields, trailing
// values and unbounded documents. New experiment artifacts use this stricter
// reader without changing historical T0 decoding.
func Unmarshal(data []byte, value any) error {
	if len(data) > 1<<20 {
		return errors.New("JSON exceeds 1MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	if err := uniqueJSON(d, 0, &nodes); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON value")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value)
}

func uniqueJSON(d *json.Decoder, depth int, nodes *int) error {
	*nodes++
	if depth > 64 || *nodes > 100000 {
		return errors.New("JSON exceeds nesting/node bounds")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}
			name = strings.ToLower(name)
			if seen[name] {
				return errors.New("duplicate JSON field")
			}
			seen[name] = true
			if err := uniqueJSON(d, depth+1, nodes); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case json.Delim('['):
		for d.More() {
			if err := uniqueJSON(d, depth+1, nodes); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	return nil
}
