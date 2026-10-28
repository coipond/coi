package container

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeQueryIncus logs "<method> <body length>" per `incus query` call and
// saves each PATCH body; GET answers with an instance description.
func fakeQueryIncus(t *testing.T) (logPath, bodyDir string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	bodyDir = t.TempDir()
	script := `#!/bin/sh
case "$3" in
  GET) echo "GET $4" >> ` + logPath + `; echo '{"description":"keep me","devices":{}}' ;;
  PATCH) n=$(ls ` + bodyDir + ` | wc -l); printf '%s' "$5" > ` + bodyDir + `/$n.json; echo "PATCH ${#5} $6" >> ` + logPath + ` ;;
  *) echo "$*" >> ` + logPath + ` ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath, bodyDir
}

func diskMounts(n int, pad string) []DiskMount {
	out := make([]DiskMount, n)
	for i := range out {
		s := strconv.Itoa(i)
		out[i] = DiskMount{Name: "protect-" + s, Source: "/host/" + pad + s, Path: "/workspace/" + pad + s, Readonly: true}
	}
	return out
}

func TestMountDisks_OnePatchForManyDevices(t *testing.T) {
	logPath, bodyDir := fakeQueryIncus(t)
	m := &Manager{ContainerName: "c1"}

	mounts := diskMounts(500, "")
	mounts[3].Shift = true
	if err := m.MountDisks(mounts); err != nil {
		t.Fatal(err)
	}
	got := calls(t, logPath)
	if len(got) != 2 || !strings.HasPrefix(got[0], "GET /1.0/instances/c1?project=") || !strings.HasPrefix(got[1], "PATCH ") {
		t.Fatalf("want one GET and one PATCH, got %v", got)
	}

	b, err := os.ReadFile(filepath.Join(bodyDir, "0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Description string                       `json:"description"`
		Devices     map[string]map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body.Description != "keep me" {
		t.Errorf("description must be sent back, got %q", body.Description)
	}
	want := map[string]string{"type": "disk", "source": "/host/7", "path": "/workspace/7", "readonly": "true"}
	if len(body.Devices) != 500 || len(body.Devices["protect-7"]) != len(want) {
		t.Fatalf("devices = %d, protect-7 = %v", len(body.Devices), body.Devices["protect-7"])
	}
	for k, v := range want {
		if body.Devices["protect-7"][k] != v {
			t.Errorf("protect-7 %s = %q, want %q", k, body.Devices["protect-7"][k], v)
		}
	}
	if body.Devices["protect-3"]["shift"] != "true" {
		t.Errorf("Shift mount must send shift=true, got %v", body.Devices["protect-3"])
	}
}

// A body over the argument limit is split; every chunk stays under it.
func TestMountDisks_ChunksLargeBodies(t *testing.T) {
	logPath, bodyDir := fakeQueryIncus(t)
	m := &Manager{ContainerName: "c1"}

	if err := m.MountDisks(diskMounts(2000, strings.Repeat("x", 60))); err != nil {
		t.Fatal(err)
	}
	patches := 0
	for _, c := range calls(t, logPath) {
		f := strings.Fields(c)
		if f[0] != "PATCH" {
			continue
		}
		patches++
		if n, _ := strconv.Atoi(f[1]); n > 128*1024 {
			t.Errorf("PATCH body %d bytes exceeds MAX_ARG_STRLEN", n)
		}
	}
	if patches < 2 {
		t.Errorf("expected the body to be split, got %d PATCH calls", patches)
	}

	names := map[string]bool{}
	for i := range patches {
		b, err := os.ReadFile(filepath.Join(bodyDir, strconv.Itoa(i)+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Devices map[string]json.RawMessage `json:"devices"`
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatal(err)
		}
		for n := range body.Devices {
			names[n] = true
		}
	}
	for i := range 2000 {
		if !names["protect-"+strconv.Itoa(i)] {
			t.Errorf("device protect-%d missing from the PATCH bodies", i)
		}
	}
}

func TestMountDisks_NoMountsNoCalls(t *testing.T) {
	logPath, _ := fakeQueryIncus(t)
	if err := (&Manager{ContainerName: "c1"}).MountDisks(nil); err != nil {
		t.Fatal(err)
	}
	if got := calls(t, logPath); len(got) != 0 {
		t.Errorf("expected no incus calls, got %v", got)
	}
}
