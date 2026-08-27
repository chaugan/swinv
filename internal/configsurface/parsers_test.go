package configsurface

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/chaugan/swinv/internal/model"
)

func TestParseCrontabSystemFormat(t *testing.T) {
	content := `# comment
SHELL=/bin/sh
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
@daily	backup	/usr/local/bin/backup.sh --all
`
	got := parseCrontab(content, "/etc/crontab", "root", true, true)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Schedule != "17 * * * *" || got[0].User != "root" {
		t.Errorf("entry 0 = %+v", got[0])
	}
	if got[1].Schedule != "@daily" || got[1].User != "backup" ||
		got[1].Executable != "/usr/local/bin/backup.sh" {
		t.Errorf("entry 1 = %+v", got[1])
	}
	if got[1].Attack != "T1053.003" {
		t.Errorf("attack = %q", got[1].Attack)
	}
}

func TestParseCrontabSpoolFormatNamesItsUser(t *testing.T) {
	got := parseCrontab("*/5 * * * * /home/alice/sync.sh\n",
		"/var/spool/cron/crontabs/alice", "alice", false, true)
	if len(got) != 1 || got[0].User != "alice" || got[0].Executable != "/home/alice/sync.sh" {
		t.Fatalf("got %+v", got)
	}
}

// Command lines carry passwords and tokens; --no-service-command drops them
// here the way it drops them from services, while the executable path - which
// is joinable and carries no secrets - stays.
func TestParseCrontabRedactsCommands(t *testing.T) {
	got := parseCrontab("0 2 * * * root /usr/bin/mysqldump -psecret db\n",
		"/etc/crontab", "root", true, false)
	if len(got) != 1 {
		t.Fatal(got)
	}
	if got[0].Command != "" {
		t.Errorf("command survived redaction: %q", got[0].Command)
	}
	if got[0].Executable != "/usr/bin/mysqldump" {
		t.Errorf("executable = %q, want the path kept", got[0].Executable)
	}
}

func TestParseUnit(t *testing.T) {
	u := parseUnit(`[Unit]
Description=x

[Service]
User=postgres
ExecStart=@/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql
ExecStart=/never/second
`)
	if u.ExecStart != "@/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql" {
		t.Errorf("ExecStart = %q", u.ExecStart)
	}
	if firstExecutable(u.ExecStart) != "/usr/lib/postgresql/16/bin/postgres" {
		t.Errorf("executable = %q", firstExecutable(u.ExecStart))
	}
	if u.User != "postgres" {
		t.Errorf("User = %q", u.User)
	}

	timer := parseUnit("[Timer]\nOnCalendar=daily\nOnBootSec=15min\nUnit=apt-daily.service\n")
	if timer.Schedule != "OnCalendar=daily OnBootSec=15min" || timer.Unit != "apt-daily.service" {
		t.Errorf("timer = %+v", timer)
	}
}

func TestFirstExecutableSkipsEnvAssignments(t *testing.T) {
	if got := firstExecutable("HOME=/root LANG=C /usr/bin/certbot renew"); got != "/usr/bin/certbot" {
		t.Errorf("got %q", got)
	}
	if got := firstExecutable("run-parts /etc/cron.daily"); got != "" {
		t.Errorf("a bare name resolved to %q; PATH is not knowledge this collector has", got)
	}
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := []byte{0xFF, 0xFE}
	for _, c := range u {
		out = binary.LittleEndian.AppendUint16(out, c)
	}
	return out
}

// The task store's files are UTF-16 with a BOM and a prolog that says so;
// the parser has to survive both.
func TestParseScheduledTaskUTF16(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary></CalendarTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Program Files\Vendor\updater.exe"</Command>
      <Arguments>/silent /token=abc</Arguments>
    </Exec>
  </Actions>
</Task>`
	got := parseScheduledTask(utf16le(xml), `\Vendor\Updater`, `C:\Windows\System32\Tasks\Vendor\Updater`, true)
	if len(got) != 1 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	e := got[0]
	if e.Kind != model.ConfigKindScheduledTask || e.Attack != "T1053.005" {
		t.Errorf("kind/attack = %q/%q", e.Kind, e.Attack)
	}
	if e.Executable != `C:\Program Files\Vendor\updater.exe` {
		t.Errorf("executable = %q", e.Executable)
	}
	if e.User != "S-1-5-18" || e.Schedule != "CalendarTrigger" {
		t.Errorf("user/schedule = %q/%q", e.User, e.Schedule)
	}
}

func TestParseScheduledTaskRedactsArguments(t *testing.T) {
	xml := `<Task><Actions><Exec><Command>C:\x.exe</Command><Arguments>/key=s3cret</Arguments></Exec></Actions></Task>`
	got := parseScheduledTask([]byte(xml), `\X`, `C:\Tasks\X`, false)
	if len(got) != 1 || got[0].Command != "" {
		t.Fatalf("arguments survived redaction: %+v", got)
	}
	if got[0].Executable != `C:\x.exe` {
		t.Errorf("executable = %q", got[0].Executable)
	}
}

func TestWindowsExecutable(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\App\app.exe" /run`: `C:\Program Files\App\app.exe`,
		`C:\Tools\run.exe /q`:                 `C:\Tools\run.exe`,
		`%SystemRoot%\system32\thing.exe`:     `%SystemRoot%\system32\thing.exe`,
	}
	for in, want := range cases {
		if got := windowsExecutable(in); got != want {
			t.Errorf("windowsExecutable(%q) = %q, want %q", in, got, want)
		}
	}
}
