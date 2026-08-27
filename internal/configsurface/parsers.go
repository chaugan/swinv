package configsurface

import (
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// parseCrontab reads one crontab. withUser is the system format
// (/etc/crontab, /etc/cron.d), where a user column sits between the schedule
// and the command; a per-user spool file names its user in its filename
// instead, passed as fallbackUser.
func parseCrontab(content, path, fallbackUser string, withUser, includeCommands bool) []model.ConfigEntry {
	var out []model.ConfigEntry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)

		// Environment assignments (SHELL=, PATH=, MAILTO=) configure the
		// jobs; they are not jobs.
		if len(fields) > 0 && strings.Contains(fields[0], "=") {
			continue
		}

		var schedule, user, command string
		switch {
		case strings.HasPrefix(line, "@"):
			// @reboot, @daily and friends: one schedule field.
			need := 2
			if withUser {
				need = 3
			}
			if len(fields) < need {
				continue
			}
			schedule = fields[0]
			rest := fields[1:]
			if withUser {
				user, rest = rest[0], rest[1:]
			}
			command = strings.Join(rest, " ")
		default:
			need := 6
			if withUser {
				need = 7
			}
			if len(fields) < need {
				continue
			}
			schedule = strings.Join(fields[:5], " ")
			rest := fields[5:]
			if withUser {
				user, rest = rest[0], rest[1:]
			}
			command = strings.Join(rest, " ")
		}
		if user == "" {
			user = fallbackUser
		}

		e := model.ConfigEntry{
			Kind:       model.ConfigKindCron,
			Path:       path,
			User:       user,
			Schedule:   schedule,
			Executable: firstExecutable(command),
			Attack:     "T1053.003",
		}
		if includeCommands {
			e.Command = command
		}
		out = append(out, e)
	}
	return out
}

// unitFile is the slice of a systemd unit this collector reads.
type unitFile struct {
	ExecStart string // first ExecStart, prefixes stripped from the program
	User      string
	Unit      string // [Timer] Unit=, the service a timer triggers
	Schedule  string // every On* trigger, joined
}

// parseUnit reads the fields above from a unit file. It is a line parser on
// purpose: systemd's full syntax (continuations, quoting, specifiers) is a
// rabbit hole, and the failure mode of a partial read here is a missing
// field on an inventory row, not a wrong system.
func parseUnit(content string) unitFile {
	var u unitFile
	var schedules []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "ExecStart":
			if u.ExecStart == "" && value != "" {
				u.ExecStart = value
			}
		case "User":
			if u.User == "" {
				u.User = value
			}
		case "Unit":
			if u.Unit == "" {
				u.Unit = value
			}
		case "OnCalendar", "OnBootSec", "OnStartupSec", "OnActiveSec",
			"OnUnitActiveSec", "OnUnitInactiveSec":
			schedules = append(schedules, key+"="+value)
		}
	}
	u.Schedule = strings.Join(schedules, " ")
	return u
}
