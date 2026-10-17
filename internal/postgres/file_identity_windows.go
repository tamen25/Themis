package postgres

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func backupFileIdentity(f *os.File) (string, error) {
	var v windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &v); e != nil {
		return "", e
	}
	return fmt.Sprintf("ntfs:%08x:%08x%08x", v.VolumeSerialNumber, v.FileIndexHigh, v.FileIndexLow), nil
}
