package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// helpFlagNames returns the bare flag names the help page mentions, e.g.
// "--no-snap, --no-flatpak" contributes two.
func helpFlagNames(t *testing.T) map[string]int {
	t.Helper()
	names := make(map[string]int)
	for _, section := range helpSections() {
		for _, f := range section.Flags {
			for _, part := range strings.Split(f.Name, ",") {
				fields := strings.Fields(part)
				if len(fields) == 0 {
					t.Fatalf("empty flag name in section %q", section.Title)
				}
				names[strings.TrimPrefix(fields[0], "--")]++
			}
		}
	}
	return names
}

func registeredFlagNames() map[string]bool {
	fs := flag.NewFlagSet("swinv", flag.ContinueOnError)
	registerFlags(fs, &config{})

	out := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) { out[f.Name] = true })
	return out
}

// TestHelpCoversEveryFlag is the reason the help page can be hand-written.
// Every registered flag must either appear in the help or be on the platform's
// deliberate omission list, and nothing may be on both.
func TestHelpCoversEveryFlag(t *testing.T) {
	registered := registeredFlagNames()
	inHelp := helpFlagNames(t)

	omitted := make(map[string]bool)
	for _, name := range helpOmittedFlags() {
		if !registered[name] {
			t.Errorf("helpOmittedFlags names %q, which is not a registered flag", name)
		}
		omitted[name] = true
	}

	for name := range registered {
		switch {
		case inHelp[name] > 0 && omitted[name]:
			t.Errorf("--%s is both documented and on the omission list", name)
		case inHelp[name] == 0 && !omitted[name]:
			t.Errorf("--%s is registered but appears in no help section, and is not deliberately omitted", name)
		case inHelp[name] > 1:
			t.Errorf("--%s appears in %d help sections; it should appear once", name, inHelp[name])
		}
	}

	for name := range inHelp {
		if !registered[name] {
			t.Errorf("help documents --%s, which no longer exists", name)
		}
	}
}

// TestHelpFitsATerminal guards the failure this replaced: descriptions long
// enough to wrap into mush. 80 columns is a serial console, an IPMI session
// and the narrow half of a tmux split.
func TestHelpFitsATerminal(t *testing.T) {
	var buf bytes.Buffer
	writeHelp(&buf)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	for i, line := range lines {
		if len(line) > helpWidth {
			t.Errorf("line %d is %d characters, over the %d limit:\n  %s",
				i+1, len(line), helpWidth, line)
		}
	}

	// Not a hard requirement, but a tripwire: the page this replaced was 75
	// ungrouped lines, and it is easy to drift back by adding "just one more"
	// description. If this fails, shorten something rather than raising it.
	if len(lines) > 80 {
		t.Errorf("help is %d lines; it is meant to be scannable, not a manual", len(lines))
	}
}

// TestHelpHasTheThingsAnOperatorNeeds checks the page still answers the
// questions it exists to answer, rather than only listing flags.
func TestHelpHasTheThingsAnOperatorNeeds(t *testing.T) {
	var buf bytes.Buffer
	writeHelp(&buf)
	help := buf.String()

	for _, want := range []string{
		"Usage:",      // how to invoke it
		"Examples:",   // something to copy
		"Exit codes:", // what a script should check
		"See also:",   // where the full reference is
	} {
		if !strings.Contains(help, want) {
			t.Errorf("help has no %q section", want)
		}
	}

	// Every example must be a command an operator can paste unchanged.
	for _, line := range strings.Split(help, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "swinv ") {
			continue
		}
		if strings.Contains(trimmed, "<") || strings.Contains(trimmed, "...") {
			t.Errorf("example is a placeholder rather than a runnable command: %q", trimmed)
		}
	}
}

// TestHelpNamesNoOtherPlatformsFlagsInSections keeps the two help pages from
// drifting into each other: a Linux page describing --volumes, or a Windows one
// describing /home, misleads exactly the operator who cannot check.
func TestHelpNamesNoOtherPlatformsFlagsInSections(t *testing.T) {
	inHelp := helpFlagNames(t)
	for _, name := range helpOmittedFlags() {
		if inHelp[name] > 0 {
			t.Errorf("--%s is on the omission list but a help section documents it", name)
		}
	}
}
