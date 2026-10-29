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
		{"minimum version", "6.1", 6, 1, false},
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
		{"exact minimum", 6, 1, true},
		{"above minimum", 6, 20, true},
		{"below minimum", 6, 0, false},
		{"higher major", 7, 0, true},
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

func TestAffectingAdvisories(t *testing.T) {
	tests := []struct {
		name  string
		major int
		minor int
		want  []string
	}{
		{"minimum", 6, 1, []string{"GHSA-wfvq-qh87-gm4j"}},
		{"last affected", 7, 4, []string{"GHSA-wfvq-qh87-gm4j"}},
		{"fixed", 7, 5, nil},
		{"newer", 8, 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &IncusVersion{Major: tt.major, Minor: tt.minor, Raw: "test"}
			var got []string
			for _, a := range AffectingAdvisories(v) {
				got = append(got, a.ID)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("AffectingAdvisories(%d.%d) = %v, want %v", tt.major, tt.minor, got, tt.want)
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

func TestFormatMinVersionError(t *testing.T) {
	v := &IncusVersion{Major: 6, Minor: 0, Raw: "6.0.3"}
	msg := FormatMinVersionError(v)

	if !strings.Contains(msg, "6.0.3") {
		t.Error("message should contain the actual version")
	}
	if !strings.Contains(msg, "6.1") {
		t.Error("message should contain the minimum version")
	}
	if !strings.Contains(msg, "zabbly") {
		t.Error("message should contain zabbly URL")
	}
}
