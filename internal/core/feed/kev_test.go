package feed

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/moathabosaaleek/cvex/internal/core/model"
)

// Serves the saved catalogue and honours If-None-Match, so the 304 path gets
// exercised against something that behaves like the real mirror.
func kevServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const etag = `"fixture"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func kevFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKEVCollect(t *testing.T) {
	srv := kevServer(t, kevFixture(t))
	k := KEV{URL: srv.URL}

	res, err := k.Collect(context.Background(), NewFetcher(), Conditional{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) == 0 {
		t.Fatal("no items parsed")
	}
	if len(res.Items) != len(res.KEV) {
		t.Errorf("%d items but %d kev rows, they should be one to one", len(res.Items), len(res.KEV))
	}
	if res.Next.ETag == "" {
		t.Error("etag not carried out of the response")
	}

	var ransomware, withCWE int
	for _, it := range res.Items {
		if it.Kind != model.KindCVE {
			t.Errorf("%s: kind is %q", it.ID, it.Kind)
		}
		if it.ID != "kev:"+it.ExternalID {
			t.Errorf("id %q does not match external id %q", it.ID, it.ExternalID)
		}
		// dateAdded is on every record in the catalogue, so a nil here means
		// the date parsing silently gave up.
		if it.Published == nil {
			t.Errorf("%s: published is nil", it.ID)
		}
		if !strings.HasPrefix(it.URL, "http") {
			t.Errorf("%s: url %q", it.ID, it.URL)
		}
		if it.Title == "" || it.Summary == "" {
			t.Errorf("%s: empty title or summary", it.ID)
		}
		if len(it.Raw) == 0 {
			t.Errorf("%s: raw payload not kept", it.ID)
		}

		cves := it.CVEs()
		if len(cves) != 1 || cves[0] != it.ExternalID {
			t.Errorf("%s: cve entity is %v", it.ID, cves)
		}
		for _, e := range it.Entities {
			if e.Kind == model.EntityCWE {
				withCWE++
				break
			}
		}
	}

	for _, e := range res.KEV {
		if e.Ransomware {
			ransomware++
		}
	}

	// The fixture was cut to include both values on purpose. If either count
	// is zero the mapping collapsed rather than the data being uniform.
	if ransomware == 0 {
		t.Error(`no entry mapped "Known" to Ransomware=true`)
	}
	if ransomware == len(res.KEV) {
		t.Error(`every entry came back ransomware, "Unknown" is not mapping to false`)
	}
	if withCWE == 0 {
		t.Error("no cwe entities extracted")
	}
}

func TestKEVNotModified(t *testing.T) {
	srv := kevServer(t, kevFixture(t))
	k := KEV{URL: srv.URL}

	res, err := k.Collect(context.Background(), NewFetcher(), Conditional{ETag: `"fixture"`})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unchanged {
		t.Error("304 did not come back as Unchanged")
	}
	if len(res.Items) != 0 {
		t.Errorf("304 returned %d items", len(res.Items))
	}
	if res.Next.ETag != `"fixture"` {
		t.Errorf("304 lost the previous etag, got %q", res.Next.ETag)
	}
}

// An empty catalogue means CISA changed the shape on us. Failing is better
// than quietly reporting that nothing is being exploited.
func TestKEVEmptyCatalogueFails(t *testing.T) {
	srv := kevServer(t, []byte(`{"catalogVersion":"2026.10.23","vulnerabilities":[]}`))
	k := KEV{URL: srv.URL}

	if _, err := k.Collect(context.Background(), NewFetcher(), Conditional{}); err == nil {
		t.Fatal("empty catalogue was accepted")
	}
}

// The nastiest failure this collector has. Unmarshal succeeds on a renamed
// field, the entry count looks healthy, every record comes out blank, and
// without the post-loop check Collect returns a successful empty Result while
// carrying the fresh ETag out. The caller stores it and every poll after that
// 304s, so the feed claims nothing is being exploited, forever, silently.
func TestKEVRenamedIDFieldFails(t *testing.T) {
	srv := kevServer(t, []byte(`{"catalogVersion":"2026.10.23","vulnerabilities":[
		{"cve_id":"CVE-2026-1","vendorProject":"Acme","dateAdded":"2026-02-02"},
		{"cve_id":"CVE-2026-2","vendorProject":"Acme","dateAdded":"2026-02-02"}
	]}`))

	_, err := (KEV{URL: srv.URL}).Collect(context.Background(), NewFetcher(), Conditional{})
	if err == nil {
		t.Fatal("a catalogue with no usable ids was accepted")
	}
}

func TestKEVUnparseableDatesFail(t *testing.T) {
	srv := kevServer(t, []byte(`{"catalogVersion":"x","vulnerabilities":[
		{"cveID":"CVE-2026-1","vulnerabilityName":"n","shortDescription":"d","dateAdded":"02/02/2026"}
	]}`))

	_, err := (KEV{URL: srv.URL}).Collect(context.Background(), NewFetcher(), Conditional{})
	if err == nil {
		t.Fatal("a date format change was accepted")
	}
}

// Raw has to be what CISA sent, not what we re-marshalled. The mirror only
// serves the current catalogue, so a field dropped on the way in cannot be
// recovered later by re-parsing.
func TestKEVRawKeepsUnmodelledFields(t *testing.T) {
	srv := kevServer(t, []byte(`{"catalogVersion":"x","vulnerabilities":[
		{"cveID":"CVE-2026-1","vulnerabilityName":"n","shortDescription":"d",
		 "dateAdded":"2026-02-02","somethingAddedLater":"keep me"}
	]}`))

	res, err := (KEV{URL: srv.URL}).Collect(context.Background(), NewFetcher(), Conditional{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(res.Items[0].Raw, []byte("somethingAddedLater")) {
		t.Errorf("raw lost a field we don't model: %s", res.Items[0].Raw)
	}
}

func TestKEVNormalisesCVEID(t *testing.T) {
	srv := kevServer(t, []byte(`{"catalogVersion":"x","vulnerabilities":[
		{"cveID":"  cve-2026-1  ","vulnerabilityName":"n","shortDescription":"d","dateAdded":"2026-02-02"}
	]}`))

	res, err := (KEV{URL: srv.URL}).Collect(context.Background(), NewFetcher(), Conditional{})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Items[0].ExternalID; got != "CVE-2026-1" {
		t.Errorf("external id %q", got)
	}
	if got := res.Items[0].ID; got != "kev:CVE-2026-1" {
		t.Errorf("item id %q", got)
	}
	if got := res.KEV[0].CVE; got != "CVE-2026-1" {
		t.Errorf("kev row cve %q", got)
	}
}

func TestLinkForPrefersAdvisory(t *testing.T) {
	cases := []struct {
		notes string
		want  string
	}{
		{"https://vendor.example/advisory", "https://vendor.example/advisory"},
		{"see https://vendor.example/a ; https://other.example/b", "https://vendor.example/a"},
		{"trailing punctuation https://vendor.example/a.", "https://vendor.example/a"},
		{"wrapped (https://vendor.example/a) and more", "https://vendor.example/a"},
		{`quoted "https://vendor.example/a" here`, "https://vendor.example/a"},
		{"", "https://nvd.nist.gov/vuln/detail/CVE-2026-1"},
		{"no link in here at all", "https://nvd.nist.gov/vuln/detail/CVE-2026-1"},
	}
	for _, c := range cases {
		if got := linkFor("CVE-2026-1", c.notes); got != c.want {
			t.Errorf("linkFor(%q) = %q, want %q", c.notes, got, c.want)
		}
	}
}
