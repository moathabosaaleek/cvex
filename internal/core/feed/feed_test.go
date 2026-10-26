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

func TestExtractCVEsOnNothing(t *testing.T) {
	if got := ExtractCVEs("", "no identifiers here"); got != nil {
		t.Errorf("want nil, got %v", got)
	}
}
