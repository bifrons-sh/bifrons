//go:build !unix

package secrets

import (
	"fmt"
	"os"
)

// openNoFollow on non-unix platforms performs a best-effort symlink check
// via Lstat before opening. There is a small TOCTOU window between Lstat
// and Open that a Linux kernel's O_NOFOLLOW would close atomically — accept
// this weaker guarantee on Windows rather than refuse to compile.
func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink at %q not allowed", path)
	}
	return os.Open(path)
}
