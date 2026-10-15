//go:build windows

package localstate

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"testing"
)

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
