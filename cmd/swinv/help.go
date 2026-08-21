package main

import (
	"fmt"
	"io"
	"strings"
)

// The help output is written by hand rather than by flag.PrintDefaults.
//
// PrintDefaults sorts alphabetically, which files --debug-stacks-after next to
// --delta-only and buries --out among diagnostics; it prints single-dash names
// while every other document here writes --flag; and it emits whatever length
// of sentence the flag registration carries, which in this tool reached 203
// characters and wrapped into mush on any normal terminal.
//
// The cost of writing it by hand is that the help and the FlagSet can drift.
// TestHelpCoversEveryFlag closes that: it asserts every registered flag appears
// here exactly once, and that no flag from the other platform leaks in.
const (
	// helpWidth is where descriptions wrap. 78 rather than the terminal width:
	// serial consoles and IPMI are 80 columns, and reflowing to fill a wide
	// terminal makes captured logs and narrow tmux panes re-wrap mid-word.
	helpWidth = 78

	// descColumn is where descriptions start. --no-auto-exclude-mounts is 24
	// characters, so the column has to clear it.
	descColumn = 28
)

type helpFlag struct {
	// Name is the flag as an operator types it, including its metavar:
	// "--out DIR". Everything up to the first space must be a registered
	// flag name, which the help test checks.
	Name string
	Desc string
}

type helpSection struct {
	Title string
	Flags []helpFlag
}

// writeHelp renders the whole help page.
//
// It goes to stdout, not stderr: a help request is a successful outcome, and
// `swinv --help | less` must not show an empty pager. Usage *errors* still go
// to stderr, and deliberately do not print this page -- an operator who
// mistyped a flag needs one line telling them which, not sixty telling them
// everything.
func writeHelp(w io.Writer) {
	fmt.Fprint(w, helpHeader)

	for _, s := range helpSections() {
		fmt.Fprintf(w, "\n%s:\n", s.Title)
		for _, f := range s.Flags {
			writeHelpFlag(w, f)
		}
	}

	fmt.Fprint(w, helpFooter)
}

// writeHelpFlag prints one flag, wrapping its description into the description
// column so continuation lines line up under the text rather than the name.
func writeHelpFlag(w io.Writer, f helpFlag) {
	name := "  " + f.Name

	pad := descColumn - len(name)
	if pad < 1 {
		// A name longer than the column gets its description on the next line
		// rather than pushing every other line out of alignment.
		fmt.Fprintf(w, "%s\n", name)
		name = ""
		pad = descColumn
	}

	indent := strings.Repeat(" ", descColumn)
	for i, line := range wrapText(f.Desc, helpWidth-descColumn) {
		if i == 0 {
			fmt.Fprintf(w, "%s%s%s\n", name, strings.Repeat(" ", pad), line)
			continue
		}
		fmt.Fprintf(w, "%s%s\n", indent, line)
	}
}

// wrapText breaks a description into lines of at most width characters,
// splitting only at spaces. A single word longer than the width is left alone:
// breaking a path or a flag name mid-token would make it uncopyable.
func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}

	var (
		lines []string
		line  strings.Builder
	)
	for _, word := range words {
		switch {
		case line.Len() == 0:
			line.WriteString(word)
		case line.Len()+1+len(word) <= width:
			line.WriteByte(' ')
			line.WriteString(word)
		default:
			lines = append(lines, line.String())
			line.Reset()
			line.WriteString(word)
		}
	}
	return append(lines, line.String())
}
