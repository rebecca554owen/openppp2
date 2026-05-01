//go:build !linux

package instance

import "os"

// Fallback: just return pipes (no PTY support on this platform)
func openPty() (*os.File, *os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	return r, w, nil
}
