package transmit

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func pinnedClient(t *testing.T, srv *httptest.Server, pins ...string) *Client {
	t.Helper()
	c, err := New(Options{
		BaseURL:        srv.URL + "/api/v1",
		Token:          "tok",
		Pins:           pins,
		RequestTimeout: 5 * time.Second,
		Attempts:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func serverPin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return SPKIPin(cert)
}

// A matching pin connects with no CA anywhere in sight, which is the whole
// point: the site with no usable trust store gets verification instead of
// --transmit-insecure.
func TestPinAcceptsTheRightKey(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := pinnedClient(t, srv, serverPin(t, srv))
	results := c.Check(context.Background())
	for _, r := range results {
		if r.Name == "reachable" && !r.OK {
			t.Fatalf("a correctly pinned connection failed: %s", r.Detail)
		}
		if r.Name == "verification" && !strings.Contains(r.Detail, "pinned") {
			t.Errorf("verification = %q, want the pin named", r.Detail)
		}
	}
}

// A wrong pin refuses the connection and names the pin it observed, so a
// first deployment is: run once, copy the pin from the error, run again.
func TestPinRefusesTheWrongKeyAndNamesTheRightOne(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	wrong := strings.Repeat("A", 43) + "="
	c := pinnedClient(t, srv, wrong)
	var reachErr string
	for _, r := range c.Check(context.Background()) {
		if r.Name == "reachable" && !r.OK {
			reachErr = r.Detail
		}
	}
	if reachErr == "" {
		t.Fatal("a wrongly pinned connection succeeded")
	}
	if !strings.Contains(reachErr, serverPin(t, srv)) {
		t.Errorf("the refusal does not name the observed pin: %s", reachErr)
	}
}

func TestPinAndInsecureContradict(t *testing.T) {
	_, err := New(Options{
		BaseURL:            "https://example.invalid/api/v1",
		Token:              "tok",
		Pins:               []string{strings.Repeat("A", 43) + "="},
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Fatal("a pin combined with insecure was accepted")
	}
}

func TestParsePinsRejectsJunk(t *testing.T) {
	if _, err := parsePins([]string{"not-base64!!"}); err == nil {
		t.Error("junk base64 was accepted as a pin")
	}
	if _, err := parsePins([]string{"c2hvcnQ="}); err == nil {
		t.Error("a short digest was accepted as a pin")
	}
}

// The preflight against a server that rejects the token must say auth failed,
// not "network trouble".
func TestCheckReportsAuthRejection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := pinnedClient(t, srv, serverPin(t, srv))
	var sawAuthFail, sawReachable bool
	for _, r := range c.Check(context.Background()) {
		if r.Name == "auth" && !r.OK {
			sawAuthFail = true
		}
		if r.Name == "reachable" && r.OK {
			sawReachable = true
		}
	}
	if !sawReachable {
		t.Error("the server answered but reachable did not pass")
	}
	if !sawAuthFail {
		t.Error("HTTP 401 did not fail the auth check")
	}
}

func TestParseTLSMin(t *testing.T) {
	if _, err := parseTLSMin("1.1"); err == nil {
		t.Error("a floor below 1.2 was accepted")
	}
	if v, err := parseTLSMin("1.3"); err != nil || v == 0 {
		t.Errorf("1.3: %v", err)
	}
}
