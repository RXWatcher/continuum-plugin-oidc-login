package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func newCapture() (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	base := hclog.New(&hclog.LoggerOptions{
		Output:     &buf,
		JSONFormat: true,
		Level:      hclog.Debug,
	})
	return New(base), &buf
}

func lastRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("decode log line %q: %v", lines[len(lines)-1], err)
	}
	return rec
}

func TestAuthDecision_SuccessLogsSubAndComponent(t *testing.T) {
	l, buf := newCapture()
	l.AuthDecision(true, ReasonSuccess, "sub-1", "actor-1", "1.2.3.4")
	rec := lastRecord(t, buf)
	if rec["event"] != "auth_decision" {
		t.Errorf("event = %v", rec["event"])
	}
	if rec["allowed"] != true {
		t.Errorf("allowed = %v", rec["allowed"])
	}
	if rec["reason"] != "success" {
		t.Errorf("reason = %v", rec["reason"])
	}
	if rec["sub"] != "sub-1" {
		t.Errorf("sub = %v", rec["sub"])
	}
	if rec["actor"] != "actor-1" {
		t.Errorf("actor = %v", rec["actor"])
	}
	if rec["peer"] != "1.2.3.4" {
		t.Errorf("peer = %v", rec["peer"])
	}
	if rec["component"] != "audit" {
		t.Errorf("component = %v", rec["component"])
	}
}

func TestAuthDecision_DenyLogsWarnAndReason(t *testing.T) {
	l, buf := newCapture()
	l.AuthDecision(false, ReasonReplay, "", "", "")
	rec := lastRecord(t, buf)
	if rec["allowed"] != false {
		t.Errorf("allowed = %v", rec["allowed"])
	}
	if rec["reason"] != "replay-detected" {
		t.Errorf("reason = %v", rec["reason"])
	}
	if rec["@level"] != "warn" {
		t.Errorf("level = %v, want warn", rec["@level"])
	}
	// Empty sub/actor/peer must be omitted, not logged blank.
	if _, ok := rec["sub"]; ok {
		t.Errorf("empty sub should be omitted")
	}
}

func TestConfigMutation_NeverLogsSecretValue(t *testing.T) {
	l, buf := newCapture()
	l.ConfigMutation("admin-7", "https://old", "https://new", true)
	rec := lastRecord(t, buf)
	if rec["event"] != "config_mutation" {
		t.Errorf("event = %v", rec["event"])
	}
	if rec["actor"] != "admin-7" {
		t.Errorf("actor = %v", rec["actor"])
	}
	if rec["issuer_url_before"] != "https://old" || rec["issuer_url_after"] != "https://new" {
		t.Errorf("issuer before/after = %v / %v", rec["issuer_url_before"], rec["issuer_url_after"])
	}
	if rec["secret_changed"] != true {
		t.Errorf("secret_changed = %v", rec["secret_changed"])
	}
}

func TestNilLogger_DoesNotPanic(t *testing.T) {
	var l *Logger
	l.AuthDecision(true, ReasonSuccess, "s", "a", "p")
	l.ConfigMutation("a", "x", "y", false)
}
