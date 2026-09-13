//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsAuditFileOpenAccess   = windows.FILE_APPEND_DATA | windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE | windows.READ_CONTROL
	windowsAuditFileAccess       = windowsAuditFileOpenAccess | windows.DELETE
	windowsAuditFileRepairAccess = windows.WRITE_DAC

	windowsAuditDirectoryOpenAccess      = windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE
	windowsAuditDirectoryDeleteChild     = windows.ACCESS_MASK(0x0040)
	windowsAuditDirectoryAccess          = windowsAuditDirectoryOpenAccess | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windowsAuditDirectoryDeleteChild
	windowsAuditDirectoryDangerousAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windowsAuditDirectoryDeleteChild | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.MAXIMUM_ALLOWED

	windowsAuditDirectoryShare   = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	windowsAuditFileShare        = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	windowsAuditTrustedFileShare = windowsAuditFileShare | windows.FILE_SHARE_DELETE
	windowsAuditFileCreated      = uintptr(2)
)

func openAuditFile(path string) (*os.File, error) {
	rootPath, parts, err := splitWindowsAuditPath(path)
	if err != nil {
		return nil, auditFileError("path")
	}
	if err := validateWindowsAuditDrive(rootPath); err != nil {
		return nil, err
	}

	currentUser, localSystem, err := windowsAuditFileSIDs()
	if err != nil {
		return nil, err
	}
	fileSecurityDescriptor, err := windowsAuditFileSecurityDescriptor(currentUser, localSystem)
	if err != nil {
		return nil, err
	}
	directorySecurityDescriptor, err := windowsAuditDirectorySecurityDescriptor(currentUser, localSystem)
	if err != nil {
		return nil, err
	}

	dirHandle, _, err := openWindowsAuditDirectoryWithSecurityDescriptorStatus(0, windowsNTPath(rootPath), windows.FILE_OPEN, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(dirHandle) }()

	for _, part := range parts[:len(parts)-1] {
		nextHandle, status, err := openWindowsAuditDirectoryWithSecurityDescriptorStatus(dirHandle, part, windows.FILE_OPEN_IF, directorySecurityDescriptor)
		if err != nil {
			return nil, err
		}
		if err := validateWindowsAuditDirectory(nextHandle, currentUser, localSystem, status == windowsAuditFileCreated); err != nil {
			_ = windows.CloseHandle(nextHandle)
			return nil, err
		}
		if err := windows.CloseHandle(dirHandle); err != nil {
			_ = windows.CloseHandle(nextHandle)
			return nil, auditFileError("parent directory")
		}
		dirHandle = nextHandle
	}

	fileHandle, status, err := openWindowsAuditHandle(dirHandle, parts[len(parts)-1],
		windowsAuditFileOpenAccess,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		windowsAuditTrustedFileShare, fileSecurityDescriptor)
	if err != nil {
		return nil, err
	}
	validatedHandle := fileHandle
	validatedClosed := false
	defer func() {
		if !validatedClosed {
			_ = windows.CloseHandle(validatedHandle)
		}
	}()
	if err := ensureWindowsAuditNotReparse(fileHandle); err != nil {
		return nil, err
	}
	validatedIdentity, err := getWindowsAuditFileIdentity(fileHandle)
	if err != nil {
		return nil, err
	}

	if status != windowsAuditFileCreated && !windowsAuditFileOwnerCompliant(fileHandle, currentUser, localSystem) {
		return nil, auditFileError("permissions")
	}
	if status != windowsAuditFileCreated && !windowsAuditFileDACLCompliant(fileHandle, currentUser, localSystem) {
		repairHandle, _, err := openWindowsAuditHandle(dirHandle, parts[len(parts)-1],
			windowsAuditFileRepairAccess,
			windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN,
			windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT,
			windowsAuditTrustedFileShare, nil)
		if err != nil {
			return nil, err
		}
		repairIdentity, err := getWindowsAuditFileIdentity(repairHandle)
		if err != nil {
			_ = windows.CloseHandle(repairHandle)
			return nil, err
		}
		if repairIdentity != validatedIdentity {
			_ = windows.CloseHandle(repairHandle)
			return nil, auditFileError("identity")
		}
		if err := restrictWindowsAuditFileWithSIDs(repairHandle, currentUser, localSystem); err != nil {
			_ = windows.CloseHandle(repairHandle)
			return nil, err
		}
		if err := windows.CloseHandle(repairHandle); err != nil {
			return nil, auditFileError("close")
		}
		if !windowsAuditFileDACLCompliant(fileHandle, currentUser, localSystem) {
			return nil, auditFileError("permissions")
		}
	}
	if !windowsAuditFileDACLCompliant(fileHandle, currentUser, localSystem) {
		return nil, auditFileError("permissions")
	}
	var share uint32 = windowsAuditFileShare
	if windowsAuditFileDeleteSharingAllowed(fileHandle, dirHandle, currentUser, localSystem) {
		share = windowsAuditTrustedFileShare
	}
	finalHandle, _, err := openWindowsAuditHandle(dirHandle, parts[len(parts)-1],
		windowsAuditFileOpenAccess,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		share, nil)
	if err != nil {
		return nil, err
	}
	if err := ensureWindowsAuditNotReparse(finalHandle); err != nil {
		_ = windows.CloseHandle(finalHandle)
		return nil, err
	}
	finalIdentity, err := getWindowsAuditFileIdentity(finalHandle)
	if err != nil {
		_ = windows.CloseHandle(finalHandle)
		return nil, err
	}
	if finalIdentity != validatedIdentity {
		_ = windows.CloseHandle(finalHandle)
		return nil, auditFileError("identity")
	}
	if !windowsAuditFileDACLCompliant(finalHandle, currentUser, localSystem) {
		_ = windows.CloseHandle(finalHandle)
		return nil, auditFileError("permissions")
	}
	if err := windows.CloseHandle(validatedHandle); err != nil {
		_ = windows.CloseHandle(finalHandle)
		return nil, auditFileError("close")
	}
	validatedClosed = true

	return os.NewFile(uintptr(finalHandle), ""), nil
}

func windowsAuditFileSIDs() (*windows.SID, *windows.SID, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || tokenUser == nil || tokenUser.User.Sid == nil || !tokenUser.User.Sid.IsValid() {
		return nil, nil, auditFileError("identity")
	}

	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil || localSystem == nil || !localSystem.IsValid() {
		return nil, nil, auditFileError("identity")
	}
	runtime.KeepAlive(tokenUser)
	return tokenUser.User.Sid, localSystem, nil
}

func windowsAuditFileSecurityDescriptor(currentUser, localSystem *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	return windowsAuditSecurityDescriptor(currentUser, localSystem, windowsAuditFileAccess)
}

func windowsAuditDirectorySecurityDescriptor(currentUser, localSystem *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	return windowsAuditSecurityDescriptor(currentUser, localSystem, windowsAuditDirectoryAccess)
}

func windowsAuditSecurityDescriptor(currentUser, localSystem *windows.SID, access windows.ACCESS_MASK) (*windows.SECURITY_DESCRIPTOR, error) {
	if currentUser == nil || localSystem == nil || !currentUser.IsValid() || !localSystem.IsValid() {
		return nil, auditFileError("identity")
	}
	currentUserString := currentUser.String()
	localSystemString := localSystem.String()
	if currentUserString == "" || localSystemString == "" {
		return nil, auditFileError("identity")
	}

	rights := fmt.Sprintf("0x%08X", access)
	sddl := "O:" + currentUserString + "D:P(A;;" + rights + ";;;" + currentUserString + ")"
	if !currentUser.Equals(localSystem) {
		sddl += "(A;;" + rights + ";;;" + localSystemString + ")"
	}

	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil || descriptor == nil {
		return nil, auditFileError("permissions")
	}
	return descriptor, nil
}

func restrictWindowsAuditFile(handle windows.Handle) error {
	currentUser, localSystem, err := windowsAuditFileSIDs()
	if err != nil {
		return err
	}
	return restrictWindowsAuditFileWithSIDs(handle, currentUser, localSystem)
}

func restrictWindowsAuditFileWithSIDs(handle windows.Handle, currentUser, localSystem *windows.SID) error {
	if currentUser == nil || localSystem == nil || !currentUser.IsValid() || !localSystem.IsValid() {
		return auditFileError("identity")
	}
	entries := windowsAuditFileAccessEntries(currentUser, localSystem)
	acl, err := windows.ACLFromEntries(entries, nil)
	runtime.KeepAlive(currentUser)
	runtime.KeepAlive(localSystem)
	if err != nil {
		return auditFileError("permissions")
	}

	err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
	runtime.KeepAlive(currentUser)
	runtime.KeepAlive(localSystem)
	if err != nil {
		return auditFileError("permissions")
	}
	return nil
}

func windowsAuditFileAccessEntries(currentUser, localSystem *windows.SID) []windows.EXPLICIT_ACCESS {
	return windowsAuditAccessEntries(windowsAuditFileAccess, currentUser, localSystem)
}

func windowsAuditDirectoryAccessEntries(currentUser, localSystem *windows.SID) []windows.EXPLICIT_ACCESS {
	return windowsAuditAccessEntries(windowsAuditDirectoryAccess, currentUser, localSystem)
}

func windowsAuditAccessEntries(access windows.ACCESS_MASK, currentUser, localSystem *windows.SID) []windows.EXPLICIT_ACCESS {
	entry := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: access,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	entries := []windows.EXPLICIT_ACCESS{entry(currentUser)}
	if !currentUser.Equals(localSystem) {
		entries = append(entries, entry(localSystem))
	}
	return entries
}

func windowsAuditFileDACLCompliant(handle windows.Handle, currentUser, localSystem *windows.SID) bool {
	return windowsAuditDACLCompliant(handle, currentUser, localSystem, windowsAuditFileAccess, true)
}

func windowsAuditDirectoryDACLCompliant(handle windows.Handle, currentUser, localSystem *windows.SID) bool {
	return windowsAuditDACLCompliant(handle, currentUser, localSystem, windowsAuditDirectoryAccess, true)
}

func validateWindowsAuditDirectory(handle windows.Handle, currentUser, localSystem *windows.SID, created bool) error {
	if created {
		if !windowsAuditDirectoryDACLCompliant(handle, currentUser, localSystem) {
			return auditFileError("permissions")
		}
		return nil
	}
	if !windowsAuditDirectorySafe(handle, currentUser, localSystem) {
		return auditFileError("permissions")
	}
	return nil
}

func windowsAuditDirectorySafe(handle windows.Handle, currentUser, localSystem *windows.SID) bool {
	if currentUser == nil || localSystem == nil || !currentUser.IsValid() || !localSystem.IsValid() {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !windowsAuditTrustedPrincipal(owner, currentUser, localSystem) {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}

	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return false
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return false
		}

		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !aceSID.IsValid() {
			return false
		}
		if !windowsAuditTrustedPrincipal(aceSID, currentUser, localSystem) &&
			windows.ACCESS_MASK(ace.Mask)&windowsAuditDirectoryDangerousAccess != 0 {
			return false
		}
	}
	return true
}

func windowsAuditFileOwnerCompliant(handle windows.Handle, currentUser, localSystem *windows.SID) bool {
	if currentUser == nil || localSystem == nil || !currentUser.IsValid() || !localSystem.IsValid() {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	return err == nil && windowsAuditOwnerCompliant(owner, currentUser, localSystem)
}

func windowsAuditFileDeleteSharingAllowed(fileHandle, directoryHandle windows.Handle, currentUser, localSystem *windows.SID) bool {
	return windowsAuditFileDACLCompliant(fileHandle, currentUser, localSystem) &&
		windowsAuditDirectorySafe(directoryHandle, currentUser, localSystem)
}

func windowsAuditTrustedPrincipal(sid, currentUser, localSystem *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	if currentUser != nil && currentUser.IsValid() && sid.Equals(currentUser) {
		return true
	}
	if localSystem != nil && localSystem.IsValid() && sid.Equals(localSystem) {
		return true
	}

	sidString := strings.ToUpper(sid.String())
	switch sidString {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544":
		return true
	default:
		return strings.HasPrefix(sidString, "S-1-5-80-")
	}
}

func windowsAuditDACLCompliant(handle windows.Handle, currentUser, localSystem *windows.SID, access windows.ACCESS_MASK, checkOwner bool) bool {
	if currentUser == nil || localSystem == nil || !currentUser.IsValid() || !localSystem.IsValid() {
		return false
	}
	securityInformation := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if checkOwner {
		securityInformation |= windows.OWNER_SECURITY_INFORMATION
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityInformation)
	if err != nil || descriptor == nil {
		return false
	}
	if checkOwner {
		owner, _, err := descriptor.Owner()
		if err != nil || !windowsAuditOwnerCompliant(owner, currentUser, localSystem) {
			return false
		}
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}

	currentUserString := currentUser.String()
	localSystemString := localSystem.String()
	if currentUserString == "" || localSystemString == "" {
		return false
	}
	wantSIDs := map[string]struct{}{
		currentUserString: {},
		localSystemString: {},
	}
	if int(dacl.AceCount) != len(wantSIDs) {
		return false
	}

	seenSIDs := make(map[string]struct{}, len(wantSIDs))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return false
		}
		if windows.ACCESS_MASK(ace.Mask) != access {
			return false
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		aceSIDString := aceSID.String()
		if _, ok := wantSIDs[aceSIDString]; !ok {
			return false
		}
		if _, ok := seenSIDs[aceSIDString]; ok {
			return false
		}
		seenSIDs[aceSIDString] = struct{}{}
	}
	return len(seenSIDs) == len(wantSIDs)
}

func windowsAuditOwnerCompliant(owner, currentUser, localSystem *windows.SID) bool {
	return owner != nil && owner.IsValid() && currentUser != nil && currentUser.IsValid() && localSystem != nil && localSystem.IsValid() &&
		(owner.Equals(currentUser) || owner.Equals(localSystem))
}

func splitWindowsAuditPath(path string) (string, []string, error) {
	if !isWindowsAuditLocalAbsolutePath(path) {
		return "", nil, os.ErrInvalid
	}
	absolute := filepath.Clean(path)
	if !filepath.IsAbs(absolute) {
		return "", nil, os.ErrInvalid
	}
	volume := filepath.VolumeName(absolute)
	if len(volume) != 2 || !isWindowsAuditDriveLetter(volume[0]) || volume[1] != ':' {
		return "", nil, os.ErrInvalid
	}
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == "." {
		return "", nil, os.ErrInvalid
	}

	parts := make([]string, 0, 4)
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." || strings.Contains(part, ":") || strings.EqualFold(part, "GLOBALROOT") || windowsAuditPathComponentIsDevice(part) {
			return "", nil, os.ErrInvalid
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return "", nil, os.ErrInvalid
	}
	return root, parts, nil
}

func isWindowsAuditLocalAbsolutePath(path string) bool {
	if len(path) < 3 || !isWindowsAuditDriveLetter(path[0]) || path[1] != ':' || !isWindowsAuditPathSeparator(path[2]) {
		return false
	}
	if strings.IndexByte(path, 0) >= 0 || strings.IndexByte(path[2:], ':') >= 0 {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	return !strings.HasPrefix(normalized, `\\`) &&
		!strings.HasPrefix(normalized, `\??\`) &&
		!strings.HasPrefix(normalized, `\device\`)
}

func isWindowsAuditDriveLetter(value byte) bool {
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

func isWindowsAuditPathSeparator(value byte) bool {
	return value == '\\' || value == '/'
}

func windowsAuditPathComponentIsDevice(component string) bool {
	base := strings.ToUpper(strings.TrimRight(component, " ."))
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = strings.TrimRight(base[:dot], " .")
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	for _, prefix := range []string{"COM", "LPT"} {
		if !strings.HasPrefix(base, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(base, prefix)
		return len([]rune(suffix)) == 1 && strings.ContainsRune("123456789¹²³", []rune(suffix)[0])
	}
	return false
}

func validateWindowsAuditDrive(root string) error {
	rootName, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return auditFileError("path")
	}
	driveType := windows.GetDriveType(rootName)
	if driveType != windows.DRIVE_FIXED && driveType != windows.DRIVE_RAMDISK {
		return auditFileError("path")
	}
	return nil
}

func openWindowsAuditDirectory(root windows.Handle, name string, disposition uint32) (windows.Handle, error) {
	return openWindowsAuditDirectoryWithSecurityDescriptor(root, name, disposition, nil)
}

func openWindowsAuditDirectoryWithSecurityDescriptor(root windows.Handle, name string, disposition uint32, securityDescriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	handle, _, err := openWindowsAuditDirectoryWithSecurityDescriptorStatus(root, name, disposition, securityDescriptor)
	return handle, err
}

func openWindowsAuditDirectoryWithSecurityDescriptorStatus(root windows.Handle, name string, disposition uint32, securityDescriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, uintptr, error) {
	handle, status, err := openWindowsAuditHandle(root, name, windowsAuditDirectoryOpenAccess,
		windows.FILE_ATTRIBUTE_DIRECTORY, disposition,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		windowsAuditDirectoryShare, securityDescriptor)
	if err != nil {
		return windows.InvalidHandle, 0, err
	}
	if err := ensureWindowsAuditNotReparse(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, 0, err
	}
	return handle, status, nil
}

func openWindowsAuditHandle(root windows.Handle, name string, access windows.ACCESS_MASK, attributes, disposition, options, share uint32, securityDescriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, uintptr, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, 0, auditFileError("path")
	}

	objectAttributes := &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      root,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: securityDescriptor,
	}
	var ioStatus windows.IO_STATUS_BLOCK
	var allocationSize int64
	var handle windows.Handle
	if err := windows.NtCreateFile(&handle, uint32(access), objectAttributes, &ioStatus, &allocationSize,
		attributes, share,
		disposition, options, 0, 0); err != nil {
		return windows.InvalidHandle, 0, auditFileError("open")
	}
	runtime.KeepAlive(objectName)
	runtime.KeepAlive(securityDescriptor)
	return handle, ioStatus.Information, nil
}

func ensureWindowsAuditNotReparse(handle windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return auditFileError("inspect")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return auditFileError("path")
	}
	return nil
}

type windowsAuditFileIdentity struct {
	volumeSerialNumber uint32
	fileIndexHigh      uint32
	fileIndexLow       uint32
}

func getWindowsAuditFileIdentity(handle windows.Handle) (windowsAuditFileIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return windowsAuditFileIdentity{}, auditFileError("inspect")
	}
	return windowsAuditFileIdentity{
		volumeSerialNumber: info.VolumeSerialNumber,
		fileIndexHigh:      info.FileIndexHigh,
		fileIndexLow:       info.FileIndexLow,
	}, nil
}

func windowsNTPath(path string) string {
	return `\??\` + path
}
