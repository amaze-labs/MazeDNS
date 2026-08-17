package logbuf

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestBufferRingEviction(t *testing.T) {
	b := New(3)
	for i := 1; i <= 5; i++ {
		b.Append(time.UnixMilli(int64(i)), "info", "m")
	}
	all := b.All()
	if len(all) != 3 {
		t.Fatalf("len=%d, want 3", len(all))
	}
	if all[0].Seq != 3 || all[2].Seq != 5 {
		t.Fatalf("kept seqs %d..%d, want 3..5", all[0].Seq, all[2].Seq)
	}
}

func TestBufferSince(t *testing.T) {
	b := New(10)
	for i := 0; i < 6; i++ {
		b.Append(time.Now(), "info", "m")
	}
	got := b.Since(2, 100)
	if len(got) != 4 || got[0].Seq != 3 {
		t.Fatalf("Since(2) = %d entries starting at %d, want 4 starting at 3", len(got), got[0].Seq)
	}
	if capped := b.Since(0, 2); len(capped) != 2 || capped[1].Seq != 2 {
		t.Fatalf("Since(0, max 2) = %+v, want seqs 1,2", capped)
	}
	if none := b.Since(6, 100); len(none) != 0 {
		t.Fatalf("Since(6) = %+v, want empty", none)
	}
}

func TestAppendEntryAssignsLocalSeq(t *testing.T) {
	b := New(4)
	b.AppendEntry(Entry{Seq: 99, TS: 123, Level: "warn", Msg: "shipped"})
	b.AppendEntry(Entry{Seq: 7, TS: 124, Level: "info", Msg: "shipped2"})
	all := b.All()
	if all[0].Seq != 1 || all[1].Seq != 2 {
		t.Fatalf("local seqs = %d,%d, want 1,2", all[0].Seq, all[1].Seq)
	}
	if all[0].TS != 123 || all[0].Level != "warn" || all[0].Msg != "shipped" {
		t.Fatalf("entry content not preserved: %+v", all[0])
	}
}

func TestHandlerRendersAttrs(t *testing.T) {
	b := New(10)
	inner := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	lg := slog.New(NewHandler(inner, b))

	lg.Info("query", "name", "example.com.", "rcode", 0)
	lg.Warn("forward failed", "err", "timeout")
	lg.Debug("hidden") // below the inner handler's level
	lg.With("node", "site-a").Error("sync failed")

	all := b.All()
	if len(all) != 3 {
		t.Fatalf("captured %d entries, want 3 (debug suppressed)", len(all))
	}
	if all[0].Level != "info" || all[0].Msg != "query name=example.com. rcode=0" {
		t.Fatalf("entry 0 = %+v", all[0])
	}
	if all[1].Level != "warn" || !strings.Contains(all[1].Msg, "err=timeout") {
		t.Fatalf("entry 1 = %+v", all[1])
	}
	if all[2].Level != "error" || !strings.Contains(all[2].Msg, "node=site-a") {
		t.Fatalf("entry 2 = %+v", all[2])
	}
}

func TestHandlerWithGroup(t *testing.T) {
	b := New(10)
	inner := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	lg := slog.New(NewHandler(inner, b))
	lg.WithGroup("req").With("id", 7).Info("done", "ms", 3)
	all := b.All()
	if len(all) != 1 || all[0].Msg != "done req.id=7 req.ms=3" {
		t.Fatalf("group rendering = %+v", all)
	}
}

func TestHandlerEnabledFollowsInner(t *testing.T) {
	b := New(10)
	inner := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewHandler(inner, b)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be disabled when inner is warn-level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("error should be enabled")
	}
}

func TestLevelHelpers(t *testing.T) {
	if LevelString(slog.LevelWarn) != "warn" || LevelString(slog.LevelDebug) != "debug" {
		t.Fatal("LevelString mapping wrong")
	}
	if !(LevelRank("error") > LevelRank("warn") && LevelRank("warn") > LevelRank("info") && LevelRank("info") > LevelRank("debug")) {
		t.Fatal("LevelRank ordering wrong")
	}
	if LevelRank("bogus") != LevelRank("debug") {
		t.Fatal("unknown labels should rank as debug")
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("short"); got != "short" {
		t.Fatalf("short lines must pass through, got %q", got)
	}
	long := strings.Repeat("y", MaxMsgLen+100)
	got := Truncate(long)
	if len(got) >= len(long) || !strings.HasSuffix(got, "…[truncated]") {
		t.Fatalf("long line not truncated: len=%d", len(got))
	}
}

func TestHandlerTruncatesHugeLines(t *testing.T) {
	b := New(4)
	inner := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.New(NewHandler(inner, b)).Info(strings.Repeat("z", MaxMsgLen*2))
	all := b.All()
	if len(all) != 1 || len(all[0].Msg) > MaxMsgLen+20 {
		t.Fatalf("captured line not truncated: len=%d", len(all[0].Msg))
	}
}
