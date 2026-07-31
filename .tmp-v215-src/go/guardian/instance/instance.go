package instance

import (
	"os/exec"
	"sync"
	"time"
)

type instance struct {
	mu sync.RWMutex
	logMu sync.RWMutex

	cfg Config

	cmd       *exec.Cmd
	running   bool
	pid       int
	startedAt *time.Time
	stoppedAt *time.Time
	lastExit  *ExitState

	restartCount    int
	restartWindowAt time.Time
	manualStop      bool
	shutdown        bool
	healthCheck     *HealthChecker
	logs            *ringBuffer
	logSubscribers  map[chan LogEntry]struct{}
	runtimeStats    map[string]string
}

type ringBuffer struct {
	items []LogEntry
	start int
	count int
}

func newRingBuffer(size int) *ringBuffer {
	if size <= 0 {
		size = 1
	}
	return &ringBuffer{items: make([]LogEntry, size)}
}

func (r *ringBuffer) add(entry LogEntry) {
	if len(r.items) == 0 {
		return
	}
	idx := (r.start + r.count) % len(r.items)
	if r.count == len(r.items) {
		r.items[r.start] = entry
		r.start = (r.start + 1) % len(r.items)
		return
	}
	r.items[idx] = entry
	r.count++
}

func (r *ringBuffer) list(n int, stream string) []LogEntry {
	if n <= 0 || n > r.count {
		n = r.count
	}
	result := make([]LogEntry, 0, n)
	for i := 0; i < r.count; i++ {
		entry := r.items[(r.start+i)%len(r.items)]
		if stream != "" && stream != "all" && stream != entry.Stream {
			continue
		}
		result = append(result, entry)
	}
	if len(result) <= n {
		return append([]LogEntry(nil), result...)
	}
	return append([]LogEntry(nil), result[len(result)-n:]...)
}
