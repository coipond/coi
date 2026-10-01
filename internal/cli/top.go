package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

var (
	topInterval float64
	topSort     string
	topProcs    bool
	topJSON     bool
	topWatch    int
)

// userHZ is the kernel clock-tick rate assumed for converting /proc/<pid>/stat
// utime/stime (in clock ticks) to seconds. Linux fixes USER_HZ at 100 on every
// mainstream architecture; Go has no portable sysconf(_SC_CLK_TCK), so this is
// the same constant ps/top-alike tools hardcode.
const userHZ = 100.0

var topCmd = &cobra.Command{
	Use:   "top [container]",
	Short: "Show per-container (or per-process) CPU/memory/IO usage",
	Long: `Show live resource usage for Coi containers, resolved to their
friendly context (alias + workspace) so you can tell which container — or which
process inside one — is loading your machine, without mapping PIDs by hand.

CPU%, disk I/O, and network I/O are sampled over a short interval (--interval),
so the command pauses briefly before printing. CPU% is aggregate across host
cores, so a container pegging 2 cores reads ~200% (same convention as top).

Views:
  coi top                 # one row per container: CPU%, memory, disk I/O, net I/O
  coi top <name|alias>    # one row per process inside that container
  coi top --procs         # processes across ALL containers (adds a CONTAINER column)

Process rows show the HOST-side PID, so you can kill a runaway directly with
'sudo kill <PID>' on the host.

Examples:
  coi top                       # all containers, busiest first
  coi top --sort mem            # sort by memory instead of CPU
  coi top -i 5                  # sample over 5 seconds
  coi top my-api                # processes inside the 'my-api' container
  coi top --procs               # every container's processes, busiest first
  coi top --watch 2             # re-render every 2s until Ctrl+C
  coi top --json                # machine-readable output`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTop,
}

func init() {
	topCmd.Flags().Float64VarP(&topInterval, "interval", "i", 2, "Seconds to sample CPU/IO rates over")
	topCmd.Flags().StringVar(&topSort, "sort", "cpu", "Sort key: cpu, mem, disk, or net (containers); cpu or mem (processes)")
	topCmd.Flags().BoolVar(&topProcs, "procs", false, "Show processes (across all containers when no container is named)")
	topCmd.Flags().BoolVar(&topJSON, "json", false, "Output as JSON")
	topCmd.Flags().IntVar(&topWatch, "watch", 0, "Re-render every N seconds until Ctrl+C (0 = one-shot)")
}

// Seams so tests can supply canned data without a live Incus/cgroup.
var (
	topListEntries      = listTopEntries
	topCollectResources = monitor.CollectResourceStats
	topCollectProcesses = monitor.CollectProcessStats
)

func runTop(cmd *cobra.Command, args []string) error {
	if topInterval <= 0 {
		return &ExitCodeError{Code: 2, Message: "invalid --interval: must be greater than 0"}
	}
	if topWatch < 0 {
		return &ExitCodeError{Code: 2, Message: "invalid --watch: must be >= 0"}
	}
	if topWatch > 0 && topJSON {
		return &ExitCodeError{Code: 2, Message: "--json is not supported with --watch"}
	}
	interval := time.Duration(topInterval * float64(time.Second))
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// A named container, or --procs, selects the process view; bare `coi top`
	// is the container view. Each view supports a different --sort vocabulary,
	// so validate against the chosen view rather than silently falling back to
	// cpu on a typo (matching how `coi list` rejects an unknown --status).
	procView := len(args) > 0 || topProcs
	if procView {
		if err := validateSortKey(topSort, procSortKeys); err != nil {
			return err
		}
	} else if err := validateSortKey(topSort, containerSortKeys); err != nil {
		return err
	}

	var only string
	if len(args) > 0 {
		resolved, err := resolveNameOrAlias(args[0])
		if err != nil {
			return err
		}
		only = resolved
	}

	// One render pass (text output). Watch mode repeats it; one-shot runs it once
	// — except one-shot --json, which the view functions handle directly.
	renderOnce := func() error {
		if procView {
			return renderProcessesText(ctx, only, interval)
		}
		return renderContainersText(ctx, interval)
	}
	if topWatch > 0 {
		return runTopWatch(ctx, renderOnce, topWatch)
	}
	if procView {
		return runTopProcesses(ctx, only, interval)
	}
	return runTopContainers(ctx, interval)
}

// runTopWatch re-renders every watchSec seconds until the context is cancelled
// (Ctrl+C). Each pass clears the screen first, mirroring `coi monitor --watch`.
// The render itself blocks ~--interval while sampling, so the effective refresh
// period is interval + watchSec.
func runTopWatch(ctx context.Context, render func() error, watchSec int) error {
	for {
		fmt.Print("\033[2J\033[H") // clear screen, cursor home
		if err := render(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		fmt.Printf("\nLast updated: %s | refresh every %ds | Press Ctrl+C to exit\n",
			time.Now().Format("15:04:05"), watchSec)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Duration(watchSec) * time.Second):
		}
	}
}

// Sort vocabularies per view. Containers can be sorted by four metrics;
// processes only carry cpu and memory.
var (
	containerSortKeys = []string{"cpu", "mem", "disk", "net"}
	procSortKeys      = []string{"cpu", "mem"}
)

// validateSortKey rejects a --sort value outside the view's vocabulary with an
// exit-code-2 usage error, so a typo is caught instead of quietly sorting by
// cpu (the default case in the sort functions).
func validateSortKey(key string, allowed []string) error {
	lower := strings.ToLower(key)
	for _, k := range allowed {
		if lower == k {
			return nil
		}
	}
	return &ExitCodeError{Code: 2, Message: fmt.Sprintf("invalid --sort %q: must be one of %s", key, strings.Join(allowed, ", "))}
}

// --- Container view ---------------------------------------------------------

// containerTopRow is one container's sampled usage plus its friendly context.
type containerTopRow struct {
	Name         string  `json:"name"`
	Alias        string  `json:"alias,omitempty"`
	Workspace    string  `json:"workspace,omitempty"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemMB        float64 `json:"memory_mb"`
	MemLimitMB   float64 `json:"memory_limit_mb,omitempty"`
	DiskReadMBs  float64 `json:"disk_read_mb_per_sec"`
	DiskWriteMBs float64 `json:"disk_write_mb_per_sec"`
	NetRxMBs     float64 `json:"net_rx_mb_per_sec"`
	NetTxMBs     float64 `json:"net_tx_mb_per_sec"`
}

func runTopContainers(ctx context.Context, interval time.Duration) error {
	if !topJSON {
		return renderContainersText(ctx, interval)
	}
	rows, err := sampleContainerRows(ctx, interval)
	if err != nil {
		return err
	}
	if rows == nil {
		fmt.Println("[]")
		return nil
	}
	sortContainerRows(rows, topSort)
	return printJSON(rows)
}

// renderContainersText samples and prints the container table (no JSON). Shared
// by the one-shot text path and watch mode.
func renderContainersText(ctx context.Context, interval time.Duration) error {
	rows, err := sampleContainerRows(ctx, interval)
	if err != nil {
		return err
	}
	if rows == nil {
		fmt.Println("No running containers.")
		return nil
	}
	sortContainerRows(rows, topSort)
	printContainerTable(rows)
	return nil
}

// sampleContainerRows enumerates running containers, samples their usage twice
// over interval, and returns one row per container (unsorted). It returns a nil
// slice when there are no running containers.
func sampleContainerRows(ctx context.Context, interval time.Duration) ([]containerTopRow, error) {
	entries0, err := topListEntries()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}
	running := make([]incusTopEntry, 0, len(entries0))
	for _, e := range entries0 {
		if container.StatusIsRunning(e.Status) {
			running = append(running, e)
		}
	}
	if len(running) == 0 {
		return nil, nil
	}

	res0 := make(map[string]monitor.ResourceStats, len(running))
	for _, e := range running {
		if r, err := topCollectResources(ctx, e.Name); err == nil {
			res0[e.Name] = r
		}
	}

	if err := sleepCtx(ctx, interval); err != nil {
		return nil, err
	}

	entries1, err := topListEntries()
	if err != nil {
		return nil, fmt.Errorf("failed to re-sample containers: %w", err)
	}
	net1 := make(map[string]incusTopEntry, len(entries1))
	for _, e := range entries1 {
		net1[e.Name] = e
	}

	workspaces := loadContainerWorkspaces()
	secs := interval.Seconds()

	rows := make([]containerTopRow, 0, len(running))
	for _, e := range running {
		r1, err := topCollectResources(ctx, e.Name)
		if err != nil {
			// Keep the container visible with a context row rather than dropping
			// it silently; usage columns stay zero.
			rows = append(rows, containerTopRow{Name: e.Name, Alias: e.alias(), Workspace: workspaces[e.Name]})
			continue
		}
		row := containerTopRow{
			Name:       e.Name,
			Alias:      e.alias(),
			Workspace:  workspaces[e.Name],
			MemMB:      r1.MemoryMB,
			MemLimitMB: r1.MemoryLimitMB,
		}
		// CPU% and disk I/O are deltas of cumulative counters, so they are only
		// meaningful with a t0 baseline. When the first sample was missing (a
		// transient collection failure), leave them at 0 rather than treating the
		// whole cumulative counter as a single-interval delta — which would render
		// an absurd multi-thousand-percent CPU spike (#707).
		if r0, ok := res0[e.Name]; ok {
			row.CPUPercent = rate(r0.CPUTimeSeconds, r1.CPUTimeSeconds, secs) * 100
			row.DiskReadMBs = rate(r0.IOReadMB, r1.IOReadMB, secs)
			row.DiskWriteMBs = rate(r0.IOWriteMB, r1.IOWriteMB, secs)
		}
		rx0, tx0 := e.netBytes()
		rx1, tx1 := net1[e.Name].netBytes()
		row.NetRxMBs = rate(float64(rx0), float64(rx1), secs) / (1024 * 1024)
		row.NetTxMBs = rate(float64(tx0), float64(tx1), secs) / (1024 * 1024)
		rows = append(rows, row)
	}
	return rows, nil
}

// sortContainerRows orders rows by the chosen key, busiest first, with the
// container name as a stable tiebreaker.
func sortContainerRows(rows []containerTopRow, key string) {
	metric := func(r containerTopRow) float64 {
		switch strings.ToLower(key) {
		case "mem":
			return r.MemMB
		case "disk":
			return r.DiskReadMBs + r.DiskWriteMBs
		case "net":
			return r.NetRxMBs + r.NetTxMBs
		default: // cpu
			return r.CPUPercent
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		mi, mj := metric(rows[i]), metric(rows[j])
		if mi != mj {
			return mi > mj
		}
		return rows[i].Name < rows[j].Name
	})
}

func printContainerTable(rows []containerTopRow) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CONTAINER\tALIAS\tCPU%\tMEM\tDISK R/W\tNET R/W\tWORKSPACE")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%.0f%%\t%s\t%s\t%s\t%s\n",
			r.Name,
			dashIfEmpty(r.Alias),
			r.CPUPercent,
			formatMem(r.MemMB, r.MemLimitMB),
			formatRate(r.DiskReadMBs)+" / "+formatRate(r.DiskWriteMBs),
			formatRate(r.NetRxMBs)+" / "+formatRate(r.NetTxMBs),
			dashIfEmpty(collapseHome(r.Workspace)),
		)
	}
	_ = w.Flush()
}

// --- Process view -----------------------------------------------------------

// procTopRow is one process's sampled usage. PID is the HOST-side PID, so it is
// directly killable from the host.
type procTopRow struct {
	Container  string  `json:"container"`
	PID        int     `json:"pid"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	MemMB      float64 `json:"memory_mb"`
	Command    string  `json:"command"`
}

func runTopProcesses(ctx context.Context, only string, interval time.Duration) error {
	names, err := resolveProcNames(only)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		if topJSON {
			fmt.Println("[]")
		} else {
			fmt.Println("No running containers.")
		}
		return nil
	}
	rows, err := sampleProcessRows(ctx, names, interval, only != "")
	if err != nil {
		return err
	}
	sortProcRows(rows, topSort)
	if topJSON {
		return printJSON(rows)
	}
	printProcessTable(rows, only == "")
	return nil
}

// renderProcessesText samples and prints the process table (no JSON). Shared by
// the one-shot text path and watch mode.
func renderProcessesText(ctx context.Context, only string, interval time.Duration) error {
	names, err := resolveProcNames(only)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Println("No running containers.")
		return nil
	}
	rows, err := sampleProcessRows(ctx, names, interval, only != "")
	if err != nil {
		return err
	}
	sortProcRows(rows, topSort)
	printProcessTable(rows, only == "")
	return nil
}

// resolveProcNames returns the containers to inspect: just `only` when set,
// otherwise every running coi container.
func resolveProcNames(only string) ([]string, error) {
	if only != "" {
		return []string{only}, nil
	}
	entries, err := topListEntries()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}
	var names []string
	for _, e := range entries {
		if container.StatusIsRunning(e.Status) {
			names = append(names, e.Name)
		}
	}
	return names, nil
}

// sampleProcessRows samples per-process CPU%/RSS across the named containers by
// reading /proc jiffies at two points interval apart. When strict is true (a
// single named container), a process-collection failure is returned; otherwise
// (across all containers) it is skipped best-effort. The returned slice is
// non-nil so an empty result marshals to `[]`, not `null`.
func sampleProcessRows(ctx context.Context, names []string, interval time.Duration, strict bool) ([]procTopRow, error) {
	type key struct {
		container string
		pid       int
	}
	// t0: record CPU jiffies for every process in each container.
	jiffies0 := make(map[key]float64)
	for _, name := range names {
		if ps, err := topCollectProcesses(ctx, name); err == nil {
			for _, p := range ps.Processes {
				if j, ok := readProcJiffies(p.PID); ok {
					jiffies0[key{name, p.PID}] = j
				}
			}
		}
	}

	if err := sleepCtx(ctx, interval); err != nil {
		return nil, err
	}
	secs := interval.Seconds()

	rows := []procTopRow{}
	for _, name := range names {
		ps, err := topCollectProcesses(ctx, name)
		if err != nil {
			if strict {
				return nil, fmt.Errorf("failed to read processes for %s: %w", name, err)
			}
			continue // best-effort across all containers
		}
		for _, p := range ps.Processes {
			j1, ok := readProcJiffies(p.PID)
			if !ok {
				continue // process exited during sampling
			}
			cpu := 0.0
			if j0, seen := jiffies0[key{name, p.PID}]; seen {
				cpu = (j1 - j0) / userHZ / secs * 100
				if cpu < 0 {
					cpu = 0
				}
			}
			rows = append(rows, procTopRow{
				Container:  name,
				PID:        p.PID,
				User:       p.User,
				CPUPercent: cpu,
				MemMB:      readProcRSSMB(p.PID),
				Command:    p.Command,
			})
		}
	}
	return rows, nil
}

func sortProcRows(rows []procTopRow, key string) {
	metric := func(r procTopRow) float64 {
		if strings.EqualFold(key, "mem") {
			return r.MemMB
		}
		return r.CPUPercent
	}
	sort.SliceStable(rows, func(i, j int) bool {
		mi, mj := metric(rows[i]), metric(rows[j])
		if mi != mj {
			return mi > mj
		}
		return rows[i].PID < rows[j].PID
	})
}

func printProcessTable(rows []procTopRow, showContainer bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if showContainer {
		fmt.Fprintln(w, "CONTAINER\tPID\tUSER\tCPU%\tMEM\tCOMMAND")
	} else {
		fmt.Fprintln(w, "PID\tUSER\tCPU%\tMEM\tCOMMAND")
	}
	for _, r := range rows {
		cmd := truncate(r.Command, 60)
		if showContainer {
			fmt.Fprintf(w, "%s\t%d\t%s\t%.0f%%\t%s\t%s\n",
				r.Container, r.PID, dashIfEmpty(r.User), r.CPUPercent, formatMem(r.MemMB, 0), cmd)
		} else {
			fmt.Fprintf(w, "%d\t%s\t%.0f%%\t%s\t%s\n",
				r.PID, dashIfEmpty(r.User), r.CPUPercent, formatMem(r.MemMB, 0), cmd)
		}
	}
	_ = w.Flush()
	if len(rows) > 0 {
		fmt.Println("\nPIDs are host-side — kill a runaway with: sudo kill <PID>")
	}
}

// --- Incus enumeration ------------------------------------------------------

// incusTopEntry is the slice of `incus list --format=json` this command needs:
// the container name/status, its alias, and per-interface network counters.
type incusTopEntry struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Config map[string]string `json:"config"`
	State  *struct {
		Network map[string]struct {
			Counters struct {
				BytesReceived int64 `json:"bytes_received"`
				BytesSent     int64 `json:"bytes_sent"`
			} `json:"counters"`
		} `json:"network"`
	} `json:"state"`
}

func (e incusTopEntry) alias() string { return e.Config["user.coi.alias"] }

// netBytes sums received/sent counters across every interface except loopback,
// so a container's real host-facing traffic is captured regardless of NIC name.
func (e incusTopEntry) netBytes() (rx, tx int64) {
	if e.State == nil {
		return 0, 0
	}
	for iface, n := range e.State.Network {
		if iface == "lo" {
			continue
		}
		rx += n.Counters.BytesReceived
		tx += n.Counters.BytesSent
	}
	return rx, tx
}

func listTopEntries() ([]incusTopEntry, error) {
	prefix := session.GetContainerPrefix()
	// `incus list`'s positional filter is a regex, but the prefix is a literal
	// (COI_CONTAINER_PREFIX may contain '.', '[', etc.), so escape it before
	// anchoring — otherwise a metacharacter prefix would match the wrong
	// containers or none at all.
	output, err := container.IncusOutput("list", "^"+regexp.QuoteMeta(prefix), "--format=json")
	if err != nil {
		return nil, err
	}
	var entries []incusTopEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// loadContainerWorkspaces maps container name -> workspace from the session
// metadata written at launch, matching how `coi list` resolves workspaces.
// Best-effort: a missing/unreadable sessions dir yields an empty map.
func loadContainerWorkspaces() map[string]string {
	out := make(map[string]string)
	if app == nil || app.cfg == nil {
		return out
	}
	toolInstance, err := getConfiguredTool(app.cfg)
	if err != nil {
		return out
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return out
	}
	sessionsDir := session.GetSessionsDir(filepath.Join(homeDir, ".coi"), toolInstance)
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sessionsDir, entry.Name(), "metadata.json"))
		if err != nil {
			continue
		}
		var md session.SessionMetadata
		if err := json.Unmarshal(data, &md); err == nil && md.ContainerName != "" {
			out[md.ContainerName] = md.Workspace
		}
	}
	return out
}

// --- /proc sampling for per-process CPU% and RSS ----------------------------

// readProcJiffies returns utime+stime (in clock ticks) from /proc/<pid>/stat.
// The comm field (field 2) can contain spaces and parentheses, so parsing
// starts after the final ')'.
func readProcJiffies(pid int) (float64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	return parseProcJiffies(string(data))
}

func parseProcJiffies(stat string) (float64, bool) {
	commEnd := strings.LastIndex(stat, ")")
	if commEnd < 0 || commEnd+2 >= len(stat) {
		return 0, false
	}
	// Fields after comm, 0-indexed: [0]=state(field3). utime=field14 -> index 11,
	// stime=field15 -> index 12.
	fields := strings.Fields(stat[commEnd+2:])
	if len(fields) < 13 {
		return 0, false
	}
	utime, err1 := strconv.ParseFloat(fields[11], 64)
	stime, err2 := strconv.ParseFloat(fields[12], 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return utime + stime, true
}

// readProcRSSMB returns resident memory in MB from /proc/<pid>/statm (field 2
// is resident pages). Returns 0 when unreadable.
func readProcRSSMB(pid int) float64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0
	}
	return pages * float64(os.Getpagesize()) / (1024 * 1024)
}

// --- formatting helpers -----------------------------------------------------

// rate returns the per-second delta of a cumulative counter, clamped at 0 so a
// counter reset (container restart) never prints a negative spike.
func rate(v0, v1, secs float64) float64 {
	if secs <= 0 {
		return 0
	}
	d := (v1 - v0) / secs
	if d < 0 {
		return 0
	}
	return d
}

// formatRate renders an MB/s value with a byte-scaled unit (reusing formatBytes).
func formatRate(mbPerSec float64) string {
	return formatBytes(int64(mbPerSec*1024*1024)) + "/s"
}

// formatMem renders memory usage, appending the limit when one is set.
func formatMem(usedMB, limitMB float64) string {
	used := formatBytes(int64(usedMB * 1024 * 1024))
	if limitMB > 0 {
		return used + "/" + formatBytes(int64(limitMB*1024*1024))
	}
	return used
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// collapseHome shortens a path under the user's home to a leading ~.
func collapseHome(path string) string {
	if path == "" {
		return ""
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if path == home {
			return "~"
		}
		if strings.HasPrefix(path, home+"/") {
			return "~" + path[len(home):]
		}
	}
	return path
}

func truncate(s string, limit int) string {
	if limit <= 1 || len(s) <= limit {
		return s
	}
	return s[:limit-1] + "…"
}

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// sleepCtx sleeps for d unless the context is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
