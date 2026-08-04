// Command vardrgate executes API authorization controls and reports findings.
//
// Subcommand dispatch lives here; the commands themselves are grouped by
// concern: execute.go runs test cases, importers.go reads specs, serve.go runs
// the HTTP API.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// version is overridden at build time with -ldflags "-X main.version=v1.2.3".
// Unset, it falls back to the module version stamped into the binary.
var version = ""

// Exit codes. Anything that executes a test case distinguishes "clean run",
// "found something", and "did not run" — a CI job needs to tell a real failure
// apart from a target it never reached.
const (
	exitOK          = 0 // ran; nothing at or above the --fail-on threshold
	exitUsage       = 1 // bad arguments, unreadable input, malformed document
	exitFindings    = 2 // findings at or above the --fail-on threshold
	exitNotExecuted = 3 // every identity errored; nothing was actually tested
)

// exitError carries a specific exit code out of a subcommand.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }

func main() {
	args := os.Args[1:]

	// A bare invocation serves, which is the documented default. Anything else
	// must name a known subcommand: falling through to serve on an unrecognised
	// argument is why `vardrgate --help` used to start a web server.
	if len(args) == 0 {
		serve()
		return
	}

	var err error
	switch args[0] {
	case "serve":
		serve()
		return
	case "run":
		err = runCases(args[1:])
	case "policy":
		err = runPolicy(args[1:])
	case "demo":
		err = runDemo(args[1:])
	case "discover":
		err = runDiscover(args[1:])
	case "gen":
		err = genTestCases(args[1:])
	case "coverage":
		err = reportCoverage(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	case "version", "-v", "--version":
		fmt.Println(versionString())
		return
	default:
		fmt.Fprintf(os.Stderr, "vardrgate: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		os.Exit(exitUsage)
	}

	if err == nil {
		return
	}

	var ee exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintln(os.Stderr, "error:", ee.err)
		}
		os.Exit(ee.code)
	}
	// flag.ContinueOnError has already printed usage for -h.
	if !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(exitUsage)
}

// versionString reports the build version, preferring an ldflags override and
// falling back to the version the Go toolchain stamps into the binary.
func versionString() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}

func usage(w io.Writer) {
	fmt.Fprint(w, `vardrgate — continuous API authorization assurance

Usage:
  vardrgate <command> [flags]

Commands:
  demo       Run a bundled policy against a local vulnerable fixture (no setup)
  policy     Compile a declarative policy and execute it
  run        Execute a job envelope or a file of test cases
  discover   Draft policies from an OpenAPI spec for you to complete
  gen        Generate starter test cases from an OpenAPI spec or Postman collection
  coverage   Report which OpenAPI operations have authorization tests
  serve      Run the HTTP API (the default when no command is given)
  version    Print the version
  help       Print this message

Run "vardrgate <command> -h" for the flags of one command.

Exit codes for commands that execute a test:
  0  ran; nothing at or above --fail-on
  1  usage or input error
  2  findings at or above --fail-on
  3  every identity errored; nothing was tested

Examples:
  vardrgate demo
  vardrgate discover --spec openapi.json --out policies/
  vardrgate policy run --policy profile.yaml --base https://api.example.com \
      --param user_id=42 --identities identities.json --fail-on high
  vardrgate run --cases cases.json --fail-on critical
`)
}
