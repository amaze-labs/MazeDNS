// Package logbuf keeps a bounded in-memory ring of recent process log lines so
// the dashboard can show them: each binary tees its slog output into a Buffer,
// agents ship new lines to the control plane on their poll cycle, and the
// control plane serves its own ring plus one ring per node. Nothing is
// persisted — history has `docker logs` semantics (lost on restart, bounded).
package logbuf

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// MaxMsgLen bounds one rendered log line. It caps memory per entry everywhere
// lines are held or shipped (rings are entry-counted, so unbounded messages
// would make their memory unbounded) and keeps any shipped batch well under
// the control plane's request body cap. Enforced at capture (Handler) and
// again at ingest, where the line may come from an untrusted agent.
const MaxMsgLen = 8 << 10

// Truncate clamps a log line to MaxMsgLen, marking the cut.
func Truncate(msg string) string {
	if len(msg) <= MaxMsgLen {
		return msg
	}
	return msg[:MaxMsgLen] + "…[truncated]"
}

// Entry is one captured log line. Seq is monotonically increasing per Buffer
// (per process boot) and is what shipping cursors advance on; TS is unix
// milliseconds.
type Entry struct {
	Seq   uint64 `json:"seq"`
	TS    int64  `json:"ts"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// Buffer is a fixed-capacity ring of Entries, safe for concurrent use.
type Buffer struct {
	mu      sync.Mutex
	entries []Entry // ring storage
	start   int     // index of the oldest entry
	count   int
	nextSeq uint64
}

// New returns a Buffer holding at most capacity entries (oldest evicted first).
func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 1
	}
	return &Buffer{entries: make([]Entry, capacity)}
}

// Append adds a line, assigning it the next sequence number.
func (b *Buffer) Append(ts time.Time, level, msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSeq++
	b.put(Entry{Seq: b.nextSeq, TS: ts.UnixMilli(), Level: level, Msg: msg})
}

// AppendEntry adds an already-formed entry (e.g. one shipped by an agent),
// assigning it a fresh local sequence number but keeping its timestamp, level,
// and message.
func (b *Buffer) AppendEntry(e Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSeq++
	e.Seq = b.nextSeq
	b.put(e)
}

// put assumes b.mu is held.
func (b *Buffer) put(e Entry) {
	if b.count < len(b.entries) {
		b.entries[(b.start+b.count)%len(b.entries)] = e
		b.count++
		return
	}
	b.entries[b.start] = e
	b.start = (b.start + 1) % len(b.entries)
}

// Since returns up to max entries with Seq > after, oldest first.
func (b *Buffer) Since(after uint64, max int) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Entry, 0, min(max, b.count))
	for i := 0; i < b.count && len(out) < max; i++ {
		e := b.entries[(b.start+i)%len(b.entries)]
		if e.Seq > after {
			out = append(out, e)
		}
	}
	return out
}

// All returns a copy of the buffered entries, oldest first.
func (b *Buffer) All() []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Entry, b.count)
	for i := range out {
		out[i] = b.entries[(b.start+i)%len(b.entries)]
	}
	return out
}

// LevelString maps a slog level to the lowercase label stored in entries.
func LevelString(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

// LevelRank orders level labels for minimum-level filtering; unknown labels
// rank as debug so they are never hidden by accident.
func LevelRank(label string) int {
	switch label {
	case "error":
		return 3
	case "warn":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// Handler is a slog.Handler that renders each record to one line in a Buffer
// and then delegates to the wrapped handler, so normal stdout logging is
// unchanged.
type Handler struct {
	inner slog.Handler
	buf   *Buffer
	attrs []slog.Attr // WithAttrs-bound attrs, keys already group-qualified
	group string      // dotted group prefix from WithGroup
}

// NewHandler tees records captured by inner into buf.
func NewHandler(inner slog.Handler, buf *Buffer) *Handler {
	return &Handler{inner: inner, buf: buf}
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	var sb strings.Builder
	sb.WriteString(rec.Message)
	appendAttr := func(a slog.Attr, group string) {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			return
		}
		sb.WriteByte(' ')
		if group != "" {
			sb.WriteString(group)
			sb.WriteByte('.')
		}
		sb.WriteString(a.Key)
		sb.WriteByte('=')
		sb.WriteString(a.Value.String())
	}
	for _, a := range h.attrs {
		appendAttr(a, "") // bound attrs carry their group prefix already
	}
	rec.Attrs(func(a slog.Attr) bool {
		appendAttr(a, h.group)
		return true
	})
	ts := rec.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	h.buf.Append(ts, LevelString(rec.Level), Truncate(sb.String()))
	return h.inner.Handle(ctx, rec)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	nh.inner = h.inner.WithAttrs(attrs)
	nh.attrs = append([]slog.Attr{}, h.attrs...)
	for _, a := range attrs {
		if h.group != "" {
			a.Key = h.group + "." + a.Key
		}
		nh.attrs = append(nh.attrs, a)
	}
	return &nh
}

func (h *Handler) WithGroup(name string) slog.Handler {
	nh := *h
	nh.inner = h.inner.WithGroup(name)
	if name != "" {
		if nh.group != "" {
			nh.group += "." + name
		} else {
			nh.group = name
		}
	}
	return &nh
}
