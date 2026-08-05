//go:build !linux

package instance

import "os"

// Fix pipe direction - master should be write end for parent to write to child's stdin
func openPty() (*os.File, *os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	return w, r, nil  // Return write end as master, read end as slave
}
