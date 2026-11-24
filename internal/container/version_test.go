package container

import (
	"strings"
	"testing"
)

func TestParseIncusVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		major   int
		minor   int
		wantErr bool
	}{
		{"standard version", "6.20", 6, 20, false},
		{"two-part version", "6.1", 6, 1, false},
		{"patch version", "6.0.3", 6, 0, false},
		{"next major", "7.0", 7, 0, false},
		{"with whitespace", "  6.5  ", 6, 5, false},
		{"empty string", "", 0, 0, true},
		{"no minor", "6", 0, 0, true},
		{"invalid major", "abc.1", 0, 0, true},
		{"invalid minor", "6.abc", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseIncusVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v.Major != tt.major {
				t.Errorf("major = %d, want %d", v.Major, tt.major)
			}
			if v.Minor != tt.minor {
				t.Errorf("minor = %d, want %d", v.Minor, tt.minor)
			}
		})
	}
}

func TestExtractServerVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			"multi-line with server version",
			"Client version: 6.20\nServer version: 6.20",
			"6.20",
			false,
		},
		{
			"multi-line different versions",
			"Client version: 6.21\nServer version: 6.18",
			"6.18",
			false,
		},
		{
			"single line fallback",
			"6.5",
			"6.5",
			false,
		},
		{
			"empty string",
			"",
			"",
			true,
		},
		{
			"whitespace only",
			"   ",
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractServerVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMeetsMinimumVersion(t *testing.T) {
	tests := []struct {
		name  string
		major int
		minor int
		want  bool
	}{
		{"exact minimum", 7, 0, true},
		{"above minimum", 7, 5, true},
		{"latest 6.x", 6, 21, false},
		{"Ubuntu 6.0", 6, 0, false},
		{"higher major", 8, 0, true},
		{"lower major", 5, 9, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &IncusVersion{Major: tt.major, Minor: tt.minor, Raw: "test"}
			got := MeetsMinimumVersion(v)
			if got != tt.want {
				t.Errorf("MeetsMinimumVersion(%d.%d) = %v, want %v", tt.major, tt.minor, got, tt.want)
			}
		})
	}
}

func TestMeetsRecommendedVersion(t *testing.T) {
	tests := []struct {
		name  string
		major int
		minor int
		want  bool
	}{
		{"below", 7, 4, false},
		{"exact", 7, 5, true},
		{"higher major", 8, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &IncusVersion{Major: tt.major, Minor: tt.minor, Raw: "test"}
			if got := MeetsRecommendedVersion(v); got != tt.want {
				t.Errorf("MeetsRecommendedVersion(%d.%d) = %v, want %v", tt.major, tt.minor, got, tt.want)
			}
		})
	}
}

func TestFormatMinServerVersionError(t *testing.T) {
	v := &IncusVersion{Major: 6, Minor: 0, Raw: "6.0.3"}

	for name, msg := range map[string]string{
		"server": FormatMinServerVersionError(v),
		"client": FormatMinClientVersionError(v),
	} {
		if !strings.Contains(msg, "Incus "+name+" version 6.0.3") {
			t.Errorf("%s message should name the part and the actual version: %q", name, msg)
		}
		if !strings.Contains(msg, "minimum required 7.0") {
			t.Errorf("%s message should contain the minimum version: %q", name, msg)
		}
		if !strings.Contains(msg, "zabbly") {
			t.Errorf("%s message should contain zabbly URL: %q", name, msg)
		}
	}
}

func TestExtractClientVersion(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    string
		wantErr bool
	}{
		{"two-line output", "Client version: 6.21\nServer version: 7.0", "6.21", false},
		{"server unreachable", "Client version: 7.5\nServer version: unreachable", "7.5", false},
		{"single-line output", "6.20", "", true},
		{"empty client version", "Client version: \nServer version: 7.0", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractClientVersion(tt.output)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractClientVersion(%q) error = %v, wantErr %v", tt.output, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckMinimumVersionOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantErr string
	}{
		{"both at minimum", "Client version: 7.0.2\nServer version: 7.0", ""},
		{"both recent", "Client version: 7.5\nServer version: 7.6", ""},
		{"old server", "Client version: 7.5\nServer version: 6.0.3", "Incus server version 6.0.3 is below the minimum required 7.0"},
		{"old client", "Client version: 6.21\nServer version: 7.5", "Incus client version 6.21 is below the minimum required 7.0"},
		{"both old reports the server", "Client version: 6.0.3\nServer version: 6.0.3", "Incus server version 6.0.3"},
		{"single-line old server", "6.20", "Incus server version 6.20"},
		{"unparseable versions are not checked", "Client version: dev\nServer version: unreachable", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkMinimumVersionOutput(tt.output)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckMinimumVersion_TranslatedOutput(t *testing.T) {
	t.Setenv("LANG", "de_DE.UTF-8")
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	fakeIncusScript(t, `if [ "$LC_ALL" = C ]; then
  printf 'Client version: 6.21\nServer version: 7.5\n'
else
  printf 'Client Version: 6.21\nServer Version: 7.5\n'
fi`)

	err := CheckMinimumVersion()
	if err == nil || !strings.Contains(err.Error(), "Incus client version 6.21") {
		t.Errorf("CheckMinimumVersion() = %v, want the old client refused", err)
	}
}
