//go:build unix

package secrets

import (
	"os"
	"syscall"
)

// openNoFollow opens path with O_NOFOLLOW so a symlink at the path fails the
// open outright (ELOOP). The kernel enforces this atomically with the open,
// eliminating the TOCTOU that a path-based Lstat+Open pair would leave.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
