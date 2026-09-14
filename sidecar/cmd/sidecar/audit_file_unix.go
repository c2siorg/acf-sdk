//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

func openAuditFile(path string) (*os.File, error) {
	base, parts, err := splitAuditPath(path)
	if err != nil {
		return nil, auditFileError("path")
	}

	dirFD, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, auditFileError("parent directory")
	}
	defer func() { _ = unix.Close(dirFD) }()
	if !unixAuditDirectorySafe(dirFD) {
		return nil, auditFileError("parent directory")
	}

	for _, part := range parts[:len(parts)-1] {
		nextFD, err := openAuditDirectory(dirFD, part)
		if err != nil {
			return nil, err
		}
		if err := unix.Close(dirFD); err != nil {
			_ = unix.Close(nextFD)
			return nil, auditFileError("parent directory")
		}
		dirFD = nextFD
	}
	if err := unixAuditTargetPreflight(dirFD, parts[len(parts)-1]); err != nil {
		return nil, err
	}

	fileFD, err := unix.Openat(dirFD, parts[len(parts)-1],
		unix.O_APPEND|unix.O_CREAT|unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, auditFileError("open")
	}
	if !unixAuditFileSafe(fileFD) {
		_ = unix.Close(fileFD)
		return nil, auditFileError("permissions")
	}
	return os.NewFile(uintptr(fileFD), ""), nil
}

func splitAuditPath(path string) (string, []string, error) {
	clean := filepath.Clean(path)
	clean = canonicalizeDarwinAuditPath(clean)
	base := "."
	if filepath.IsAbs(clean) {
		base = string(filepath.Separator)
		clean = strings.TrimPrefix(clean, base)
	}

	parts := make([]string, 0, 4)
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return "", nil, errors.New("audit path has no file component")
	}
	return base, parts, nil
}

func canonicalizeDarwinAuditPath(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	switch {
	case path == "/tmp" || strings.HasPrefix(path, "/tmp/"):
		return "/private" + path
	case path == "/var" || strings.HasPrefix(path, "/var/"):
		return "/private" + path
	default:
		return path
	}
}

func openAuditDirectory(parentFD int, name string) (int, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Openat(parentFD, name, flags, 0)
	if err == nil {
		if !unixAuditDirectorySafe(fd) {
			_ = unix.Close(fd)
			return -1, auditFileError("parent directory")
		}
		return fd, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return -1, auditFileError("parent directory")
	}

	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, auditFileError("parent directory")
	}
	fd, err = unix.Openat(parentFD, name, flags, 0)
	if err != nil {
		return -1, auditFileError("parent directory")
	}
	if !unixAuditDirectorySafe(fd) {
		_ = unix.Close(fd)
		return -1, auditFileError("parent directory")
	}
	return fd, nil
}

func unixAuditDirectorySafe(fd int) bool {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false
	}

	mode := uint32(stat.Mode)
	if mode&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) || !unixAuditOwnerTrusted(uint32(stat.Uid)) {
		return false
	}
	return unixAuditDirectoryModeSafe(mode)
}

func unixAuditFileSafe(fd int) bool {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false
	}
	return unixAuditFileStatSafe(&stat)
}

func unixAuditTargetPreflight(parentFD int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return auditFileError("inspect")
	}
	if !unixAuditFileStatSafe(&stat) {
		return auditFileError("permissions")
	}
	return nil
}

func unixAuditFileStatSafe(stat *unix.Stat_t) bool {
	if stat == nil {
		return false
	}

	mode := uint32(stat.Mode)
	if mode&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || !unixAuditOwnerTrusted(uint32(stat.Uid)) {
		return false
	}
	if mode&uint32(unix.S_ISUID|unix.S_ISGID) != 0 {
		return false
	}
	return mode&0o022 == 0
}

func unixAuditOwnerTrusted(uid uint32) bool {
	euid := unix.Geteuid()
	return uid == 0 || (euid >= 0 && uid == uint32(euid))
}

func unixAuditDirectoryModeSafe(mode uint32) bool {
	if mode&uint32(unix.S_ISUID|unix.S_ISGID) != 0 {
		return false
	}
	if mode&0o022 == 0 {
		return true
	}
	return mode&0o1000 != 0
}
