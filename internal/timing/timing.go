// Package timing is an opt-in, zero-cost-when-off wall-clock profiler for a
// single coi invocation.
//
// Almost everything coi does is a subprocess: one `incus` call after another.
// So "where did the 12 seconds go" is answered by recording, for every timed
// span, when it started relative to process start and how long it took — then
// printing them as a nested timeline. Spans nest by containment (a phase
// contains the incus calls it made), which is computed at report time from the
// intervals themselves rather than tracked with a counter, so spans recorded
// from background goroutines can't corrupt the depth of the main pipeline.
//
// Nothing is recorded unless COI_TIMING_DEBUG is set, so instrumentation can live on
// the hot paths permanently:
//
//	COI_TIMING_DEBUG=1                    # timeline + totals to stderr at exit
//	COI_TIMING_DEBUG_JSON=/tmp/run.json   # machine-readable dump for benchmarking
package timing

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Categories used by the instrumentation. They group the totals in the report.
const (
	CatPhase    = "phase"    // a session pipeline phase
	CatTeardown = "teardown" // a pipeline teardown, named after the phase that registered it
	CatStep     = "step"     // a named chunk of work inside a phase
	CatIncus    = "incus"    // one incus subprocess
	CatHost     = "host"     // one non-incus host subprocess
)

var (
	// processStart is set when the package is initialized, which for a CLI is
	// close enough to process start to use as the timeline's zero.
	processStart = time.Now()

	enabled  bool
	jsonPath string

	mu      sync.Mutex
	records []Record
)

// Record is one completed span.
type Record struct {
	Category string        `json:"category"`
	Label    string        `json:"label"`
	Start    time.Duration `json:"-"` // offset from process start
	Duration time.Duration `json:"-"`

	StartMS float64 `json:"start_ms"`
	DurMS   float64 `json:"duration_ms"`
}

func init() {
	enabled = truthy(os.Getenv("COI_TIMING_DEBUG"))
	jsonPath = os.Getenv("COI_TIMING_DEBUG_JSON")
	if jsonPath != "" {
		enabled = true
	}
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}

// Enabled reports whether spans are being recorded. Callers only need this to
// skip expensive label construction; Start is already a no-op when off.
func Enabled() bool { return enabled }

// noop is returned by Start when timing is off, so the disabled path allocates
// nothing.
var noop = func() {}

// Start opens a span and returns the function that closes it. The idiom is:
//
//	defer timing.Start(timing.CatStep, "wait-for-ready")()
//
// Calling the returned function more than once records the span more than once,
// so call it exactly once (defer does).
func Start(category, label string) func() {
	if !enabled {
		return noop
	}
	start := time.Since(processStart)
	return func() {
		dur := time.Since(processStart) - start
		mu.Lock()
		records = append(records, Record{
			Category: category,
			Label:    label,
			Start:    start,
			Duration: dur,
			StartMS:  ms(start),
			DurMS:    ms(dur),
		})
		mu.Unlock()
	}
}

// SinceStart records a span from process start until now — for time spent
// before any instrumented code ran (runtime/package init, CLI parsing).
func SinceStart(category, label string) {
	if !enabled {
		return
	}
	dur := time.Since(processStart)
	mu.Lock()
	records = append(records, Record{Category: category, Label: label, Duration: dur, DurMS: ms(dur)})
	mu.Unlock()
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// Records returns a copy of everything recorded so far, in completion order.
func Records() []Record {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Record, len(records))
	copy(out, records)
	return out
}

// Reset drops all recorded spans. For tests.
func Reset() {
	mu.Lock()
	records = nil
	mu.Unlock()
}

// Report writes the timeline and totals to w, and additionally dumps JSON to
// COI_TIMING_DEBUG_JSON when that is set. No-op when timing is off or nothing was
// recorded. Intended to be deferred once, as high in the call stack as
// possible, so it sees the teardowns too.
func Report(w io.Writer) {
	if !enabled {
		return
	}
	recs := Records()
	total := time.Since(processStart)
	if jsonPath != "" {
		if err := writeJSON(jsonPath, total, recs); err != nil {
			fmt.Fprintf(w, "coi timing: could not write %s: %v\n", jsonPath, err)
		}
	}
	if len(recs) == 0 {
		return
	}
	if truthy(os.Getenv("COI_TIMING_DEBUG")) {
		fmt.Fprint(w, Format(total, recs))
	}
}

// Format renders the timeline and totals. Split out from Report so it can be
// tested without touching the environment or the global record list.
func Format(total time.Duration, recs []Record) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== coi timing === total %s\n", dur(total))
	fmt.Fprintf(&b, "%9s %9s  %s\n", "at", "took", "what")

	for _, n := range nest(recs) {
		fmt.Fprintf(&b, "%9s %9s  %s%s %s\n",
			dur(n.rec.Start), dur(n.rec.Duration),
			strings.Repeat("  ", n.depth), n.rec.Category, trunc(n.rec.Label, 110))
	}

	fmt.Fprintf(&b, "\nby category:\n")
	fmt.Fprintf(&b, "%9s %9s  %s\n", "wall", "self", "category")
	for _, c := range categoryTotals(recs) {
		fmt.Fprintf(&b, "%9s %9s  %-9s %d span(s)\n", dur(c.wall), dur(c.self), c.category, c.count)
	}

	if slow := slowest(recs, CatIncus, 10); len(slow) > 0 {
		fmt.Fprintf(&b, "\nslowest %s spans:\n", CatIncus)
		for _, r := range slow {
			fmt.Fprintf(&b, "%19s  %s\n", dur(r.Duration), trunc(r.Label, 110))
		}
	}
	return b.String()
}

type nested struct {
	rec   Record
	depth int
}

// nest orders spans by start time and derives each one's depth from
// containment: a span that started while an earlier span was still open is
// printed inside it.
func nest(recs []Record) []nested {
	sorted := make([]Record, len(recs))
	copy(sorted, recs)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		// Same start: the longer span is the container, so it comes first.
		return sorted[i].Duration > sorted[j].Duration
	})

	out := make([]nested, 0, len(sorted))
	var stack []time.Duration // end times of currently open spans
	for _, r := range sorted {
		for len(stack) > 0 && stack[len(stack)-1] <= r.Start {
			stack = stack[:len(stack)-1]
		}
		out = append(out, nested{rec: r, depth: len(stack)})
		stack = append(stack, r.Start+r.Duration)
	}
	return out
}

type catTotal struct {
	category string
	wall     time.Duration // sum of span durations
	self     time.Duration // wall minus time covered by spans nested inside them
	count    int
}

func categoryTotals(recs []Record) []catTotal {
	byCat := map[string]*catTotal{}
	for _, r := range recs {
		c, ok := byCat[r.Category]
		if !ok {
			c = &catTotal{category: r.Category}
			byCat[r.Category] = c
		}
		c.wall += r.Duration
		c.self += r.Duration - childCoverage(recs, r)
		c.count++
	}
	out := make([]catTotal, 0, len(byCat))
	for _, c := range byCat {
		out = append(out, *c)
	}
	// Ranked by self time: wall double-counts nesting (a step containing a
	// step sums both), which would put a category that costs nothing on top.
	sort.Slice(out, func(i, j int) bool { return out[i].self > out[j].self })
	return out
}

// childCoverage returns how much of parent's interval is covered by spans
// strictly contained in it, merging overlaps so concurrent children are not
// double-counted. Used to turn a phase's wall time into self time — the part
// not explained by the calls it made.
func childCoverage(recs []Record, parent Record) time.Duration {
	pEnd := parent.Start + parent.Duration
	type iv struct{ s, e time.Duration }
	var kids []iv
	for _, r := range recs {
		if r == parent {
			continue
		}
		end := r.Start + r.Duration
		contained := r.Start >= parent.Start && end <= pEnd
		// A span with the identical interval as the parent (e.g. a phase whose
		// single incus call is the whole phase) is contained by the tie-break
		// above only for the one sorted first; treat equal intervals as
		// children only when the child is shorter, which the < below handles.
		if !contained || r.Duration >= parent.Duration {
			continue
		}
		kids = append(kids, iv{r.Start, end})
	}
	if len(kids) == 0 {
		return 0
	}
	sort.Slice(kids, func(i, j int) bool { return kids[i].s < kids[j].s })
	var covered time.Duration
	cur := kids[0]
	for _, k := range kids[1:] {
		if k.s > cur.e {
			covered += cur.e - cur.s
			cur = k
			continue
		}
		if k.e > cur.e {
			cur.e = k.e
		}
	}
	return covered + (cur.e - cur.s)
}

func slowest(recs []Record, category string, n int) []Record {
	var in []Record
	for _, r := range recs {
		if r.Category == category {
			in = append(in, r)
		}
	}
	sort.Slice(in, func(i, j int) bool { return in[i].Duration > in[j].Duration })
	if len(in) > n {
		in = in[:n]
	}
	return in
}

type jsonDump struct {
	TotalMS float64  `json:"total_ms"`
	Records []Record `json:"records"`
}

func writeJSON(path string, total time.Duration, recs []Record) error {
	data, err := json.MarshalIndent(jsonDump{TotalMS: ms(total), Records: recs}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// dur formats a duration at a fixed millisecond precision so the columns line
// up and small spans stay comparable (Go's default switches units mid-column).
func dur(d time.Duration) string {
	return fmt.Sprintf("%.3fs", d.Seconds())
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
