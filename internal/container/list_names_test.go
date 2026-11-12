package container

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeListIncus puts an `incus` on PATH that answers `list` with listOut and
// `query` per the case below, and returns the call log path.
func fakeListIncus(t *testing.T, listOut string) (logPath string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "list.out")
	if err := os.WriteFile(out, []byte(listOut), 0o644); err != nil {
		t.Fatal(err)
	}
	return fakeIncusScript(t, `case "$*" in
  *" list "*) cat `+out+` ;;
  "query /1.0/instances/gone?"*) echo "Error: Instance not found" >&2; exit 1 ;;
  "query "*) echo '{"status":"Running"}' ;;
esac`)
}

func TestParseNamesCSV(t *testing.T) {
	for in, want := range map[string][]string{
		"":     nil,
		"\n":   nil,
		"c1\n": {"c1"},
		"coi-ab12cd34-1\ncoi-ab12cd34-10\r\n\n  web  \n": {"coi-ab12cd34-1", "coi-ab12cd34-10", "web"},
	} {
		if got := parseNamesCSV(in); !reflect.DeepEqual(got, want) {
			t.Errorf("parseNamesCSV(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListContainerNames(t *testing.T) {
	logPath := fakeListIncus(t, "coi-ab12cd34-1\ncoi-ab12cd34-2\n")

	names, err := ListContainerNames("^coi-ab12cd34-")
	if err != nil || !reflect.DeepEqual(names, []string{"coi-ab12cd34-1", "coi-ab12cd34-2"}) {
		t.Fatalf("names = %q, %v", names, err)
	}
	if _, err := ListContainerNames(""); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--project default list ^coi-ab12cd34- --format=csv --columns=n",
		"--project default list --format=csv --columns=n",
	}
	if got := calls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func TestListContainerNames_Empty(t *testing.T) {
	fakeListIncus(t, "")
	names, err := ListContainerNames("^coi-")
	if err != nil || len(names) != 0 {
		t.Errorf("names = %q, %v", names, err)
	}
}

func TestListContainers(t *testing.T) {
	logPath := fakeListIncus(t, "coi-a-1\nweb\ncoi-b-2\n")

	got, err := ListContainers("^coi-")
	if err != nil || !reflect.DeepEqual(got, []string{"coi-a-1", "coi-b-2"}) {
		t.Errorf("ListContainers = %q, %v", got, err)
	}
	if strings.Contains(strings.Join(calls(t, logPath), "\n"), "json") {
		t.Error("ListContainers must not ask for the JSON state")
	}
	if _, err := ListContainers("("); err == nil {
		t.Error("invalid pattern: want error")
	}
}

func TestContainerFullJSON(t *testing.T) {
	logPath := fakeListIncus(t, "")

	if out, err := ContainerFullJSON("c1"); err != nil || strings.TrimSpace(out) != `{"status":"Running"}` {
		t.Errorf("ContainerFullJSON = %q, %v", out, err)
	}
	if got := calls(t, logPath); len(got) != 1 || got[0] != "query /1.0/instances/c1?recursion=1&project=default" {
		t.Errorf("calls = %q", got)
	}
	if _, err := ContainerFullJSON("gone"); !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("missing instance: err = %v, want ErrContainerNotFound", err)
	}
}

func TestParseRunningNamesCSV(t *testing.T) {
	for in, want := range map[string][]string{
		"":                                     nil,
		"c1,STOPPED\n":                         nil,
		"c1,RUNNING\nc2,STOPPED\nc3,RUNNING\n": {"c1", "c3"},
		"c1,RUNNING\r\n\nbad\n":                {"c1"},
	} {
		if got := parseRunningNamesCSV(in); !reflect.DeepEqual(got, want) {
			t.Errorf("parseRunningNamesCSV(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListRunningContainerNames(t *testing.T) {
	logPath := fakeListIncus(t, "c1,RUNNING\nc2,FROZEN\nc3,RUNNING\n")

	names, err := ListRunningContainerNames()
	if err != nil || !reflect.DeepEqual(names, []string{"c1", "c3"}) {
		t.Fatalf("names = %q, %v", names, err)
	}
	if got := calls(t, logPath); !reflect.DeepEqual(got, []string{"--project default list --format=csv --columns=ns"}) {
		t.Errorf("calls = %q", got)
	}
}
