package timing

import (
	"strings"
	"testing"
	"time"
)

func rec(cat, label string, startMS, durMS int) Record {
	s := time.Duration(startMS) * time.Millisecond
	d := time.Duration(durMS) * time.Millisecond
	return Record{Category: cat, Label: label, Start: s, Duration: d, StartMS: ms(s), DurMS: ms(d)}
}

func TestStartRecordsNothingWhenDisabled(t *testing.T) {
	Reset()
	prev := enabled
	enabled = false
	defer func() { enabled = prev }()

	Start(CatStep, "ignored")()

	if got := Records(); len(got) != 0 {
		t.Fatalf("expected no records with timing disabled, got %d", len(got))
	}
}

func TestStartRecordsSpanWhenEnabled(t *testing.T) {
	Reset()
	prev := enabled
	enabled = true
	defer func() { enabled = prev; Reset() }()

	stop := Start(CatIncus, "start c1")
	time.Sleep(2 * time.Millisecond)
	stop()

	got := Records()
	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	if got[0].Category != CatIncus || got[0].Label != "start c1" {
		t.Fatalf("unexpected record: %+v", got[0])
	}
	if got[0].Duration < 2*time.Millisecond {
		t.Fatalf("duration %s shorter than the sleep", got[0].Duration)
	}
	if got[0].DurMS <= 0 {
		t.Fatalf("DurMS not populated: %+v", got[0])
	}
}

func TestNestByContainment(t *testing.T) {
	// A phase containing two incus calls, then a later sibling phase.
	recs := []Record{
		rec(CatIncus, "init", 10, 100),
		rec(CatIncus, "start", 120, 200),
		rec(CatPhase, "launch-container", 5, 400),
		rec(CatPhase, "run-command", 500, 50),
	}
	got := nest(recs)

	want := []struct {
		label string
		depth int
	}{
		{"launch-container", 0},
		{"init", 1},
		{"start", 1},
		{"run-command", 0},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d nested rows, got %d", len(want), len(got))
	}
	for i, w := range want {
		if got[i].rec.Label != w.label || got[i].depth != w.depth {
			t.Errorf("row %d: got (%s, depth %d), want (%s, depth %d)",
				i, got[i].rec.Label, got[i].depth, w.label, w.depth)
		}
	}
}

func TestChildCoverageMergesOverlaps(t *testing.T) {
	parent := rec(CatPhase, "p", 0, 1000)
	// 0-300 and 200-500 overlap (covering 0-500); 600-700 is separate.
	recs := []Record{
		parent,
		rec(CatIncus, "a", 0, 300),
		rec(CatIncus, "b", 200, 300),
		rec(CatIncus, "c", 600, 100),
	}
	got := childCoverage(recs, parent)
	if want := 600 * time.Millisecond; got != want {
		t.Fatalf("childCoverage = %s, want %s", got, want)
	}
}

func TestChildCoverageIgnoresSpansOutsideParent(t *testing.T) {
	parent := rec(CatPhase, "p", 100, 100)
	recs := []Record{
		parent,
		rec(CatIncus, "before", 0, 50),
		rec(CatIncus, "straddling", 150, 100), // ends after the parent
	}
	if got := childCoverage(recs, parent); got != 0 {
		t.Fatalf("childCoverage = %s, want 0", got)
	}
}

func TestCategoryTotalsSelfTimeExcludesChildren(t *testing.T) {
	recs := []Record{
		rec(CatPhase, "launch-container", 0, 1000),
		rec(CatIncus, "init", 100, 400),
		rec(CatIncus, "start", 500, 300),
	}
	totals := categoryTotals(recs)

	byCat := map[string]catTotal{}
	for _, c := range totals {
		byCat[c.category] = c
	}
	phase := byCat[CatPhase]
	if phase.wall != time.Second {
		t.Errorf("phase wall = %s, want 1s", phase.wall)
	}
	if want := 300 * time.Millisecond; phase.self != want {
		t.Errorf("phase self = %s, want %s", phase.self, want)
	}
	incus := byCat[CatIncus]
	if incus.count != 2 || incus.wall != 700*time.Millisecond {
		t.Errorf("incus totals = %+v, want 2 spans / 700ms", incus)
	}
}

func TestFormatIncludesTimelineAndTotals(t *testing.T) {
	out := Format(2*time.Second, []Record{
		rec(CatPhase, "launch-container", 0, 1500),
		rec(CatIncus, "init images:coi-default c1", 10, 900),
	})

	for _, want := range []string{
		"=== coi timing === total 2.000s",
		"launch-container",
		"init images:coi-default c1",
		"by category",
		"slowest incus spans",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestTruthy(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "on", "/tmp/x.json"} {
		if !truthy(v) {
			t.Errorf("truthy(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", " OFF "} {
		if truthy(v) {
			t.Errorf("truthy(%q) = true, want false", v)
		}
	}
}

// SinceStart records a span from process start, and nothing when disabled.
func TestSinceStart(t *testing.T) {
	prev := enabled
	t.Cleanup(func() { enabled = prev; Reset() })

	enabled = false
	Reset()
	SinceStart(CatStep, "startup")
	if len(Records()) != 0 {
		t.Fatal("disabled: must record nothing")
	}

	enabled = true
	SinceStart(CatStep, "startup")
	recs := Records()
	if len(recs) != 1 || recs[0].Label != "startup" || recs[0].Start != 0 || recs[0].Duration <= 0 {
		t.Errorf("got %+v", recs)
	}
}
