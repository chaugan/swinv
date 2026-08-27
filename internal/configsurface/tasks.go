package configsurface

import (
	"bytes"
	"encoding/xml"
	"strings"
	"unicode/utf16"

	"github.com/chaugan/swinv/internal/model"
)

// Windows Scheduled Task XML, the slice this collector reads. The files under
// \Windows\System32\Tasks are UTF-16 with a BOM, which encoding/xml does not
// speak, so decoding starts with a transcode. This parser lives outside the
// windows build tag so the Linux CI can test it against fixture files.

type taskXML struct {
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
	Principals struct {
		Principal []struct {
			UserID string `xml:"UserId"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Triggers struct {
		Inner []rawTrigger `xml:",any"`
	} `xml:"Triggers"`
}

type rawTrigger struct {
	XMLName xml.Name
}

// parseScheduledTask reads one task file. name is the task's path under the
// Tasks directory, which is how Windows names tasks.
func parseScheduledTask(raw []byte, name, path string, includeCommands bool) []model.ConfigEntry {
	text := decodeUTF16IfNeeded(raw)

	// Task XML declares utf-16 in its prolog even after transcoding, and
	// encoding/xml refuses a declared charset it cannot read. Dropping the
	// prolog sidesteps the claim entirely.
	text = text[prologEnd(text):]

	var t taskXML
	if err := xml.NewDecoder(bytes.NewReader(text)).Decode(&t); err != nil {
		return nil
	}

	user := ""
	if len(t.Principals.Principal) > 0 {
		user = t.Principals.Principal[0].UserID
	}
	var triggers []string
	for _, tr := range t.Triggers.Inner {
		triggers = append(triggers, tr.XMLName.Local)
	}

	var out []model.ConfigEntry
	for _, exec := range t.Actions.Exec {
		command := strings.TrimSpace(exec.Command + " " + exec.Arguments)
		e := model.ConfigEntry{
			Kind:       model.ConfigKindScheduledTask,
			Name:       name,
			Path:       path,
			User:       user,
			Schedule:   strings.Join(triggers, " "),
			Executable: windowsExecutable(exec.Command),
			Attack:     "T1053.005",
		}
		if includeCommands {
			e.Command = command
		}
		out = append(out, e)
	}
	return out
}

// prologEnd skips past the <?xml ...?> declaration whose encoding claim no
// longer matches the transcoded bytes.
func prologEnd(b []byte) int {
	if bytes.HasPrefix(b, []byte("<?xml")) {
		if i := bytes.Index(b, []byte("?>")); i >= 0 {
			return i + 2
		}
	}
	return 0
}

// decodeUTF16IfNeeded transcodes the UTF-16 task XML to UTF-8, keyed on the
// BOM, and hands anything else back untouched.
func decodeUTF16IfNeeded(raw []byte) []byte {
	le := bytes.HasPrefix(raw, []byte{0xFF, 0xFE})
	be := bytes.HasPrefix(raw, []byte{0xFE, 0xFF})
	if !le && !be {
		return raw
	}
	raw = raw[2:]
	u16 := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		if le {
			u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
		} else {
			u16 = append(u16, uint16(raw[i])<<8|uint16(raw[i+1]))
		}
	}
	return []byte(string(utf16.Decode(u16)))
}

// windowsExecutable normalises a task or autorun command's program: quotes
// stripped, environment variables left as written - expanding them would
// claim knowledge of an environment this collector does not have.
func windowsExecutable(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	if strings.HasPrefix(command, `"`) {
		if end := strings.Index(command[1:], `"`); end >= 0 {
			return command[1 : end+1]
		}
		return strings.Trim(command, `"`)
	}
	// An unquoted command line: the program ends at the first space that
	// follows an extension-looking token, or the first space at all.
	if i := strings.IndexAny(command, " \t"); i > 0 {
		return command[:i]
	}
	return command
}
