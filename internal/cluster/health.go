package cluster

import (
	"sync/atomic"
	"time"
)

// SyncHealth records when this node last reached the control plane for its
// config snapshot, and the last failure. It exists before the agent does (an
// agent still enrolling has simply never synced), so it is created by the caller
// and handed to the agent with SetSyncHealth.
type SyncHealth struct {
	lastOK  atomic.Int64 // unix ms
	lastErr atomic.Int64 // unix ms
	errText atomic.Pointer[string]
}

// SyncStatus is a point-in-time view of SyncHealth. Zero times mean "never since
// start".
type SyncStatus struct {
	LastOK    time.Time
	LastError time.Time
	Error     string
}

func (h *SyncHealth) ok() { h.lastOK.Store(time.Now().UnixMilli()) }

func (h *SyncHealth) failed(err error) {
	msg := err.Error()
	h.errText.Store(&msg)
	h.lastErr.Store(time.Now().UnixMilli())
}

// Status returns the last sync success and failure.
func (h *SyncHealth) Status() SyncStatus {
	var s SyncStatus
	if ms := h.lastOK.Load(); ms != 0 {
		s.LastOK = time.UnixMilli(ms)
	}
	if ms := h.lastErr.Load(); ms != 0 {
		s.LastError = time.UnixMilli(ms)
	}
	if p := h.errText.Load(); p != nil {
		s.Error = *p
	}
	return s
}

// SetSyncHealth makes the agent record each snapshot poll's outcome in h.
func (a *Agent) SetSyncHealth(h *SyncHealth) { a.syncHealth = h }
