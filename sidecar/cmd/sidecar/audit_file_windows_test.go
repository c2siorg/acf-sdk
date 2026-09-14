//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOpenAuditFileUsesProtectedUserAndSystemDACL(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	file, err := openAuditFile(path)
	if err != nil {
		t.Fatalf("openAuditFile: %v", err)
	}
	defer file.Close()

	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("get LocalSystem SID: %v", err)
	}

	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("get file security: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("get descriptor control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL control = %#x, want protected DACL", control)
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("get DACL: %v", err)
	}
	wantSIDs := map[string]struct{}{
		tokenUser.User.Sid.String(): {},
		localSystem.String():        {},
	}
	wantACECount := len(windowsAuditFileAccessEntries(tokenUser.User.Sid, localSystem))
	if int(dacl.AceCount) != wantACECount {
		t.Fatalf("DACL ACE count = %d, want %d", dacl.AceCount, wantACECount)
	}

	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatalf("get ACE %d: %v", index, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("ACE %d type = %d, want allowed ACE", index, ace.Header.AceType)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			t.Errorf("ACE %d is inherited", index)
		}
		if windows.ACCESS_MASK(ace.Mask) != windowsAuditFileAccess {
			t.Errorf("ACE %d mask = %#x, want %#x", index, ace.Mask, windowsAuditFileAccess)
		}

		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		aceSIDString := aceSID.String()
		if _, ok := wantSIDs[aceSIDString]; !ok {
			t.Errorf("ACE %d SID = %s, want current user or LocalSystem", index, aceSIDString)
		}
		delete(wantSIDs, aceSIDString)
	}
	if len(wantSIDs) != 0 {
		t.Errorf("DACL is missing %d required SID entries", len(wantSIDs))
	}
	if !windowsAuditFileDACLCompliant(windows.Handle(file.Fd()), tokenUser.User.Sid, localSystem) {
		t.Fatal("created audit file failed DACL compliance check")
	}
}

func TestOpenAuditFileRepairsExistingDACL(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatalf("create audit file: %v", err)
	}

	file, err := openAuditFile(path)
	if err != nil {
		t.Fatalf("openAuditFile: %v", err)
	}
	defer file.Close()

	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("get LocalSystem SID: %v", err)
	}
	if !windowsAuditFileDACLCompliant(windows.Handle(file.Fd()), tokenUser.User.Sid, localSystem) {
		t.Fatal("existing audit file failed DACL compliance check")
	}
}

func TestWindowsAuditFileDACLRejectsExtraRights(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	file, err := openAuditFile(path)
	if err != nil {
		t.Fatalf("openAuditFile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}

	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("get LocalSystem SID: %v", err)
	}

	handle, _, err := openWindowsAuditHandle(0, windowsNTPath(path),
		windowsAuditFileOpenAccess|windows.WRITE_DAC,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		windowsAuditFileShare, nil)
	if err != nil {
		t.Fatalf("open audit file for DACL setup: %v", err)
	}
	defer windows.CloseHandle(handle)

	entries := windowsAuditFileAccessEntries(tokenUser.User.Sid, localSystem)
	entries[0].AccessPermissions |= windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build extra-rights DACL: %v", err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatalf("set extra-rights DACL: %v", err)
	}

	if windowsAuditFileDACLCompliant(handle, tokenUser.User.Sid, localSystem) {
		t.Fatal("DACL with extra rights passed compliance check")
	}
}

func TestWindowsAuditFileDACLRejectsUntrustedDelete(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	file, err := openAuditFile(path)
	if err != nil {
		t.Fatalf("openAuditFile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}

	currentUser, localSystem, err := windowsAuditFileSIDs()
	if err != nil {
		t.Fatalf("get audit file SIDs: %v", err)
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatalf("create Everyone SID: %v", err)
	}
	handle, _, err := openWindowsAuditHandle(0, windowsNTPath(path),
		windowsAuditFileOpenAccess|windows.WRITE_DAC,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		windowsAuditFileShare, nil)
	if err != nil {
		t.Fatalf("open audit file for DACL setup: %v", err)
	}
	defer windows.CloseHandle(handle)

	entries := windowsAuditFileAccessEntries(currentUser, localSystem)
	entries = append(entries, windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.DELETE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	})
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build untrusted-delete DACL: %v", err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatalf("set untrusted-delete DACL: %v", err)
	}

	if windowsAuditFileDACLCompliant(handle, currentUser, localSystem) {
		t.Fatal("DACL granting delete to Everyone passed compliance check")
	}
}

func TestOpenAuditFileAllowsTrustedDeleteSharing(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit-parent", "audit.jsonl")
	file, err := openAuditFile(path)
	if err != nil {
		t.Fatalf("openAuditFile: %v", err)
	}
	defer file.Close()

	deleteHandle, _, err := openWindowsAuditHandle(0, windowsNTPath(path),
		windows.DELETE,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT,
		windowsAuditTrustedFileShare, nil)
	if err != nil {
		t.Fatalf("open audit file for trusted delete: %v", err)
	}
	if err := windows.CloseHandle(deleteHandle); err != nil {
		t.Fatalf("close trusted delete handle: %v", err)
	}
}

func TestWindowsAuditFileOpenAccessOmitsWriteDac(t *testing.T) {
	if windowsAuditFileOpenAccess&windows.WRITE_DAC != 0 {
		t.Fatalf("open access = %#x, includes WRITE_DAC", windowsAuditFileOpenAccess)
	}
	if windowsAuditFileOpenAccess&windows.WRITE_OWNER != 0 {
		t.Fatalf("open access = %#x, includes WRITE_OWNER", windowsAuditFileOpenAccess)
	}
}

func TestWindowsAuditFileRepairAccessOnlyWritesDACL(t *testing.T) {
	if windowsAuditFileRepairAccess != windows.WRITE_DAC {
		t.Fatalf("repair access = %#x, want WRITE_DAC only", windowsAuditFileRepairAccess)
	}
}

func TestWindowsAuditFileShareRequiresTrustedACL(t *testing.T) {
	if windowsAuditFileShare&windows.FILE_SHARE_DELETE != 0 {
		t.Fatalf("initial file share = %#x, includes FILE_SHARE_DELETE", windowsAuditFileShare)
	}
	if windowsAuditTrustedFileShare&windows.FILE_SHARE_DELETE == 0 {
		t.Fatalf("trusted file share = %#x, omits FILE_SHARE_DELETE", windowsAuditTrustedFileShare)
	}
	if windowsAuditFileAccess&windows.DELETE == 0 {
		t.Fatalf("file access = %#x, omits DELETE", windowsAuditFileAccess)
	}
}

func TestWindowsAuditFileAccessIsMinimal(t *testing.T) {
	if windowsAuditFileAccess != windowsAuditFileOpenAccess|windows.DELETE {
		t.Fatalf("file access = %#x, want open access plus DELETE", windowsAuditFileAccess)
	}
	for _, right := range []windows.ACCESS_MASK{
		windows.FILE_READ_DATA,
		windows.FILE_READ_EA,
		windows.FILE_WRITE_DATA,
		windows.FILE_WRITE_EA,
		windows.WRITE_DAC,
		windows.WRITE_OWNER,
	} {
		if windowsAuditFileAccess&right != 0 {
			t.Errorf("file access = %#x, includes unneeded right %#x", windowsAuditFileAccess, right)
		}
	}
}

func TestWindowsAuditFileAccessEntriesDoNotInherit(t *testing.T) {
	currentUser, err := windows.StringToSid("S-1-5-21-1-2-3-4")
	if err != nil {
		t.Fatalf("create user SID: %v", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("get LocalSystem SID: %v", err)
	}

	entries := windowsAuditFileAccessEntries(currentUser, localSystem)
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	for index, entry := range entries {
		if entry.AccessPermissions != windowsAuditFileAccess {
			t.Errorf("entry %d access = %#x, want %#x", index, entry.AccessPermissions, windowsAuditFileAccess)
		}
		if entry.AccessMode != windows.GRANT_ACCESS {
			t.Errorf("entry %d mode = %d, want grant", index, entry.AccessMode)
		}
		if entry.Inheritance != windows.NO_INHERITANCE {
			t.Errorf("entry %d inheritance = %#x, want no inheritance", index, entry.Inheritance)
		}
	}
}

func TestWindowsAuditFileAccessEntriesDeduplicateLocalSystem(t *testing.T) {
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("get LocalSystem SID: %v", err)
	}

	entries := windowsAuditFileAccessEntries(localSystem, localSystem)
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
}

func TestOpenAuditFileCreatesProtectedParentDirectories(t *testing.T) {
	root := realAuditTempDir(t)
	firstParent := filepath.Join(root, "audit-parent")
	secondParent := filepath.Join(firstParent, "nested")
	file, err := openAuditFile(filepath.Join(secondParent, "audit.jsonl"))
	if err != nil {
		t.Fatalf("openAuditFile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}

	currentUser, localSystem, err := windowsAuditFileSIDs()
	if err != nil {
		t.Fatalf("get audit file SIDs: %v", err)
	}
	for _, path := range []string{firstParent, secondParent} {
		handle, err := openWindowsAuditDirectory(0, windowsNTPath(path), windows.FILE_OPEN)
		if err != nil {
			t.Fatalf("open parent directory %s: %v", path, err)
		}
		compliant := windowsAuditDirectoryDACLCompliant(handle, currentUser, localSystem)
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			t.Fatalf("close parent directory: %v", closeErr)
		}
		if !compliant {
			t.Fatalf("parent directory %s failed protected DACL compliance", path)
		}
	}
}

func TestOpenAuditFileReturnsNormalHandleAfterRepair(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	file, err := openAuditFile(path)
	if err != nil {
		t.Fatalf("create audit file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}

	currentUser, localSystem, err := windowsAuditFileSIDs()
	if err != nil {
		t.Fatalf("get audit file SIDs: %v", err)
	}
	setupHandle, _, err := openWindowsAuditHandle(0, windowsNTPath(path),
		windowsAuditFileOpenAccess|windows.WRITE_DAC,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		windowsAuditFileShare, nil)
	if err != nil {
		t.Fatalf("open audit file for DACL setup: %v", err)
	}
	ownerBefore := windowsAuditTestOwnerString(t, setupHandle)
	entries := windowsAuditFileAccessEntries(currentUser, localSystem)
	entries[0].AccessPermissions |= windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		_ = windows.CloseHandle(setupHandle)
		t.Fatalf("build extra-rights DACL: %v", err)
	}
	if err := windows.SetSecurityInfo(setupHandle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		_ = windows.CloseHandle(setupHandle)
		t.Fatalf("set extra-rights DACL: %v", err)
	}
	if err := windows.CloseHandle(setupHandle); err != nil {
		t.Fatalf("close DACL setup handle: %v", err)
	}

	file, err = openAuditFile(path)
	if err != nil {
		t.Fatalf("repair audit file: %v", err)
	}
	defer file.Close()
	if !windowsAuditFileDACLCompliant(windows.Handle(file.Fd()), currentUser, localSystem) {
		t.Fatal("repaired audit file failed compliance check")
	}
	if ownerAfter := windowsAuditTestOwnerString(t, windows.Handle(file.Fd())); ownerAfter != ownerBefore {
		t.Fatalf("repaired audit file owner = %s, want preserved owner %s", ownerAfter, ownerBefore)
	}
	if err := windows.SetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err == nil {
		t.Fatal("repaired audit file returned a privileged handle")
	}
}

func TestOpenAuditFileRejectsUnsafeExistingParentDACL(t *testing.T) {
	root := realAuditTempDir(t)
	parent := filepath.Join(root, "trusted-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("create parent directory: %v", err)
	}

	currentUser, localSystem, err := windowsAuditFileSIDs()
	if err != nil {
		t.Fatalf("get audit file SIDs: %v", err)
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatalf("create Everyone SID: %v", err)
	}
	entries := windowsAuditDirectoryAccessEntries(currentUser, localSystem)
	entries = append(entries, windows.EXPLICIT_ACCESS{
		AccessPermissions: windowsAuditDirectoryAccess,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	})
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build parent DACL: %v", err)
	}
	setupHandle, _, err := openWindowsAuditHandle(0, windowsNTPath(parent),
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.FILE_GENERIC_EXECUTE|windows.WRITE_DAC,
		windows.FILE_ATTRIBUTE_DIRECTORY, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		windowsAuditDirectoryShare, nil)
	if err != nil {
		t.Fatalf("open parent for DACL setup: %v", err)
	}
	if err := windows.SetSecurityInfo(setupHandle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		_ = windows.CloseHandle(setupHandle)
		t.Fatalf("set parent DACL: %v", err)
	}
	if err := windows.CloseHandle(setupHandle); err != nil {
		t.Fatalf("close parent setup handle: %v", err)
	}

	path := filepath.Join(parent, "audit.jsonl")
	if _, err := openAuditFile(path); err == nil {
		t.Fatal("openAuditFile accepted an untrusted parent DACL")
	} else if strings.Contains(err.Error(), path) {
		t.Fatalf("audit error exposed configured path: %v", err)
	}

	parentHandle, err := openWindowsAuditDirectory(0, windowsNTPath(parent), windows.FILE_OPEN)
	if err != nil {
		t.Fatalf("reopen parent directory: %v", err)
	}
	descriptor, err := windows.GetSecurityInfo(parentHandle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		_ = windows.CloseHandle(parentHandle)
		t.Fatalf("get parent security: %v", err)
	}
	daclAfter, _, err := descriptor.DACL()
	if err != nil {
		_ = windows.CloseHandle(parentHandle)
		t.Fatalf("get parent DACL: %v", err)
	}
	if int(daclAfter.AceCount) != len(entries) {
		_ = windows.CloseHandle(parentHandle)
		t.Fatalf("parent DACL ACE count = %d, want %d", daclAfter.AceCount, len(entries))
	}
	foundEveryone := false
	for index := uint16(0); index < daclAfter.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(daclAfter, uint32(index), &ace); err != nil {
			_ = windows.CloseHandle(parentHandle)
			t.Fatalf("get parent ACE %d: %v", index, err)
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID.Equals(everyone) {
			foundEveryone = true
		}
	}
	if err := windows.CloseHandle(parentHandle); err != nil {
		t.Fatalf("close reopened parent: %v", err)
	}
	if !foundEveryone {
		t.Fatal("existing parent DACL was rewritten")
	}
}

func TestSplitWindowsAuditPathRejectsUnsafeForms(t *testing.T) {
	for _, path := range []string{
		`relative\audit.jsonl`,
		`\rooted\audit.jsonl`,
		`C:relative\audit.jsonl`,
		`\\server\share\audit.jsonl`,
		`\\?\C:\audit.jsonl`,
		`\\.\pipe\audit`,
		`\??\C:\audit.jsonl`,
		`\Device\HarddiskVolume1\audit.jsonl`,
		`C:\audit:stream`,
		`C:\GLOBALROOT\Device\audit`,
		`C:\CON\audit`,
		`C:\CON .txt`,
		`C:\COM¹.txt`,
		`C:\LPT³ .log`,
	} {
		if _, _, err := splitWindowsAuditPath(path); err == nil {
			t.Errorf("splitWindowsAuditPath accepted %q", path)
		}
	}

	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	if _, _, err := splitWindowsAuditPath(path); err != nil {
		t.Fatalf("splitWindowsAuditPath rejected local absolute path: %v", err)
	}
}

func TestWindowsAuditPathComponentRejectsReservedDeviceForms(t *testing.T) {
	for _, component := range []string{
		"CON", "CON.txt", "CON .txt",
		"PRN.log", "AUX .log", "NUL.txt", "CONIN$.txt", "CONOUT$ .log",
		"COM1", "COM9.txt", "COM1 .txt", "LPT1", "LPT9.log", "LPT1 .log",
		"COM¹", "COM².txt", "COM³ .txt", "LPT¹", "LPT².log", "LPT³ .log",
	} {
		if !windowsAuditPathComponentIsDevice(component) {
			t.Errorf("windowsAuditPathComponentIsDevice(%q) = false, want true", component)
		}
	}

	for _, component := range []string{"COM0", "COM10.txt", "LPT0", "LPT10.log", "COMX.txt", "CONSOLE.txt"} {
		if windowsAuditPathComponentIsDevice(component) {
			t.Errorf("windowsAuditPathComponentIsDevice(%q) = true, want false", component)
		}
	}
}

func TestWindowsAuditOwnerComplianceAcceptsOnlyUserOrSystem(t *testing.T) {
	currentUser, localSystem, err := windowsAuditFileSIDs()
	if err != nil {
		t.Fatalf("get audit file SIDs: %v", err)
	}
	otherOwner, err := windows.StringToSid("S-1-5-21-1-2-3-4")
	if err != nil {
		t.Fatalf("create other owner SID: %v", err)
	}

	if !windowsAuditOwnerCompliant(currentUser, currentUser, localSystem) {
		t.Fatal("current user owner was rejected")
	}
	if !windowsAuditOwnerCompliant(localSystem, currentUser, localSystem) {
		t.Fatal("LocalSystem owner was rejected")
	}
	if windowsAuditOwnerCompliant(otherOwner, currentUser, localSystem) {
		t.Fatal("untrusted owner was accepted")
	}
}

func windowsAuditTestOwnerString(t *testing.T, handle windows.Handle) string {
	t.Helper()

	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("get owner security: %v", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatalf("get owner: %v", err)
	}
	return owner.String()
}
