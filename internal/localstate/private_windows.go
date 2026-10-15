package localstate

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func ownerSD(dir bool) (*windows.SECURITY_DESCRIPTOR, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	flags := ""
	if dir {
		flags = "OICI"
	}
	return windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;" + u.User.Sid.String() + ")")
}
func protect(path string, dir bool) error {
	sd, err := ownerSD(dir)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func checkPrivate(path string, info os.FileInfo) error {
	want, err := ownerSD(info.IsDir())
	if err != nil {
		return err
	}
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// Windows may retain AI/AR bookkeeping after protecting an ACL. Clear only
	// those bits in this in-memory copy; the protected bit and every ACE must
	// still exactly match the owner-only descriptor.
	if err := actual.SetControl(windows.SE_DACL_AUTO_INHERITED|windows.SE_DACL_AUTO_INHERIT_REQ, 0); err != nil {
		return err
	}
	if actual.String() != want.String() {
		return fmt.Errorf("local state requires an owner-only protected DACL: %s", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !owner.Equals(u.User.Sid) {
		return fmt.Errorf("local state owner differs from current process user")
	}
	return nil
}

// File.Sync flushes data. Windows does not expose POSIX directory fsync here;
// power loss kills the process-only fault as well. No stronger disk claim is made.
func SyncDirectory(string) error { return nil }
