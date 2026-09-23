//go:build pubsub && !windows

package pubsubc2

import (
	"context"
	"strings"
	"testing"
)

func TestExecuteCommand(t *testing.T) {
	out, exitCode := executeCommand(context.Background(), "printf evc2-ok")
	if exitCode != 0 {
		t.Fatalf("executeCommand exit code = %d, want 0; output: %q", exitCode, out)
	}
	if got, want := string(out), "evc2-ok"; got != want {
		t.Fatalf("executeCommand output = %q, want %q", got, want)
	}
}

func TestExecuteCommandFailure(t *testing.T) {
	out, exitCode := executeCommand(context.Background(), "printf failed; exit 7")
	if exitCode != 7 {
		t.Fatalf("executeCommand exit code = %d, want 7; output: %q", exitCode, out)
	}
	if !strings.Contains(string(out), "[exit: exit status 7]") {
		t.Fatalf("executeCommand output %q does not contain exit status", out)
	}
}

func TestCommandOutputEncoding(t *testing.T) {
	if got, want := commandOutputEncoding(), "utf-8"; got != want {
		t.Fatalf("commandOutputEncoding() = %q, want %q", got, want)
	}
}
