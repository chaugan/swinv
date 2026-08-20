package main

import "testing"

func TestTrimToDepthGoesDeeperUnderUsers(t *testing.T) {
	cases := map[string]string{
		// Ordinary paths group at two components.
		`C:\Program Files\Adobe\Reader\x.dll`: `C:\Program Files\Adobe`,
		`C:\Windows\WinSxS\amd64_x\y.dll`:     `C:\Windows\WinSxS`,
		`C:\Qt\6.7.2\msvc\bin\q.dll`:          `C:\Qt\6.7.2`,

		// Per-user paths go deeper, because "C:\Users\chris" collapses every
		// per-user install into one line and hides where they actually are.
		`C:\Users\chris\AppData\Local\Programs\VSCode\code.exe`: `C:\Users\chris\AppData\Local\Programs`,
		`C:\Users\chris\AppData\Roaming\npm\node_modules\x.dll`: `C:\Users\chris\AppData\Roaming\npm`,

		// Shorter than the depth: drop the file name, keep the rest.
		`C:\Windows\notepad.exe`: `C:\Windows`,
		`C:\pagefile.dll`:        `C:\`,
	}

	for path, want := range cases {
		if got := trimToDepth(path, "C:", 2); got != want {
			t.Errorf("trimToDepth(%q) = %q, want %q", path, got, want)
		}
	}
}
