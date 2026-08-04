package main

import (
	"bytes"
	"strings"
	"testing"
)

// Every command the dispatcher accepts must appear in the help text. A command
// that exists but is undocumented is invisible: the CLI has no other discovery
// mechanism.
func TestUsage_DocumentsEveryCommand(t *testing.T) {
	var b bytes.Buffer
	usage(&b)
	got := b.String()

	for _, cmd := range []string{"demo", "policy", "run", "gen", "coverage", "serve", "version", "help"} {
		if !strings.Contains(got, cmd) {
			t.Errorf("usage does not mention the %q command:\n%s", cmd, got)
		}
	}
}

// The exit codes are the CI contract. If they are not in the help text, the
// only way to learn them is to read the source.
func TestUsage_DocumentsExitCodes(t *testing.T) {
	var b bytes.Buffer
	usage(&b)
	got := b.String()

	for _, want := range []string{"--fail-on", "nothing was tested", "0 ", "1 ", "2 ", "3 "} {
		if !strings.Contains(got, want) {
			t.Errorf("usage is missing %q:\n%s", want, got)
		}
	}
}

func TestVersionString_PrefersLdflagsOverride(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v1.2.3"
	if got := versionString(); got != "v1.2.3" {
		t.Errorf("versionString() = %q, want %q", got, "v1.2.3")
	}
}

func TestVersionString_NeverEmpty(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	// Unset, it falls back to build info and finally to "dev". A version string
	// that renders as empty would make `vardrgate version` look broken.
	version = ""
	if got := versionString(); got == "" {
		t.Error("versionString() returned an empty string")
	}
}
