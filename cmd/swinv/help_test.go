package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"unicode/utf8"
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
		// Runes, not bytes: a terminal column holds a character, and a
		// multi-byte one still occupies exactly one. The help page is
		// currently all ASCII, so this is the cheap half of the guard --
		// TestWrapTextCountsCharactersNotBytes is the half that actually
		// exercises it, and it keeps an em dash on purpose for that reason.
		// Measuring in bytes failed a line that was exactly at the limit,
		// on Windows CI only, back when the header carried em dashes.
		if n := utf8.RuneCountInString(line); n > helpWidth {
			t.Errorf("line %d is %d characters, over the %d limit:\n  %s",
				i+1, n, helpWidth, line)
		}
	}

	// Not a hard requirement, but a tripwire: the page this replaced was 75
	// ungrouped lines, and it is easy to drift back by adding "just one more"
	// description. If this fails, shorten something rather than raising it.
	//
	// Raised from 80 to 100 when transmission arrived: seven flags, a section
	// heading and two more exit codes are a genuinely new surface rather than
	// description creep, and the page is still grouped.
	//
	// Raised to 110 when transmission grew its deployment surface (issue #9,
	// nine flags compressed into six rows) and the configuration surface
	// arrived (issue #13, one row). Anything that pushes past this should be
	// a `man 8 swinv` entry instead.
	//
	// Raised to 113 when the HTML report arrived: two flags (--html-report,
	// --report-from) in one row whose combined names outrun the description
	// column, so the entry spans a name line and a wrapped description - a
	// genuinely new output surface, not description creep.
	if len(lines) > 113 {
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

// TestWrapTextCountsCharactersNotBytes pins the bug that made the Windows help
// fail CI while looking fine: Go's len() counts bytes, a terminal column holds
// a character, and an em dash is three bytes. Measuring in bytes wraps
// non-ASCII text two columns early per dash and misreports line width.
func TestWrapTextCountsCharactersNotBytes(t *testing.T) {
	// Twelve two-character words. In runes that is 12*2 + 11 spaces = 35.
	// In bytes it is 12*4 + 11 = 59, so a byte-based wrapper would split this
	// across two lines at a width of 40.
	const word = "—x" // em dash (3 bytes) plus one ASCII character
	words := make([]string, 12)
	for i := range words {
		words[i] = word
	}
	line := strings.Join(words, " ")

	got := wrapText(line, 40)
	if len(got) != 1 {
		t.Errorf("wrapped into %d lines, want 1: the text is 35 characters wide, only 59 bytes", len(got))
		for i, l := range got {
			t.Logf("  line %d: %q", i, l)
		}
	}
}

// TestWrapTextRespectsWidth is the other half: nothing may exceed the width.
func TestWrapTextRespectsWidth(t *testing.T) {
	const width = 20
	text := "the quick brown fox jumps over the lazy dog and keeps on running onwards"

	for _, line := range wrapText(text, width) {
		if n := utf8.RuneCountInString(line); n > width {
			t.Errorf("line %q is %d characters, over %d", line, n, width)
		}
	}

	// A single word longer than the width is left whole rather than broken:
	// splitting a path or a flag name mid-token makes it uncopyable.
	long := strings.Repeat("x", width+10)
	if got := wrapText(long, width); len(got) != 1 || got[0] != long {
		t.Errorf("wrapText broke an over-long word: %q", got)
	}
}
