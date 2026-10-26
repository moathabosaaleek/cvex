package feed

import (
	"testing"

	"github.com/moathabosaaleek/cvex/internal/core/model"
)

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs(
		"Attackers are exploiting cve-2026-1234, and CVE-2026-1234 again.",
		"See also CVE-2021-44228 (Log4Shell) plus CVE-2026-103300.",
		"CVE-20-1 and CVE-2026-12 are not CVE ids",
	)

	want := []string{"CVE-2026-1234", "CVE-2021-44228", "CVE-2026-103300"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, e := range got {
		if e.Kind != model.EntityCVE {
			t.Errorf("entity %d has kind %q", i, e.Kind)
		}
		if e.Value != want[i] {
			t.Errorf("entity %d is %q, want %q", i, e.Value, want[i])
		}
	}
}

func TestExtractCVEsBoundaries(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Used to come back as CVE-2026-1234567 and link the story to a
		// different vulnerability entirely.
		{"See CVE-2026-12345678 today", "CVE-2026-12345678"},
		{"xCVE-2026-1234y", ""},
		{"CVE-2026-123 is too short", ""},
		{"ends the line: CVE-2026-1234", "CVE-2026-1234"},
	}

	for _, c := range cases {
		got := ExtractCVEs(c.in)
		if c.want == "" {
			if got != nil {
				t.Errorf("%q matched %v, want nothing", c.in, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Value != c.want {
			t.Errorf("%q gave %v, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractCVEsOnNothing(t *testing.T) {
	if got := ExtractCVEs("", "no identifiers here"); got != nil {
		t.Errorf("want nil, got %v", got)
	}
}
