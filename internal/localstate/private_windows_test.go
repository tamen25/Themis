//go:build windows

package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectionPinsOwnerWhenDefaultOwnerIsAdministrators(t *testing.T) {
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []bool{true, false} {
		t.Run(map[bool]string{true: "directory", false: "file"}[directory], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "new-state")
			if directory {
				err = os.Mkdir(path, 0700)
			} else {
				err = os.WriteFile(path, nil, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Elevated Windows runners can assign their default group owner to
			// new files. Exercise that ownership without changing a process token.
			err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admin, nil, nil, nil)
			if errors.Is(err, windows.ERROR_INVALID_OWNER) || errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Skipf("assigning the Administrators owner is unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := protect(path, directory); err != nil {
				t.Fatal(err)
			}
			if err := Check(path); err != nil {
				t.Fatalf("new state must belong to the current user with a private DACL: %v", err)
			}
		})
	}
}

func TestRejectPublicDACL(t *testing.T) {
	dir, err := CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	defer protect(dir, true)
	if Check(dir) == nil {
		t.Fatal("public DACL accepted")
	}
}
