//go:build windows

package wincollect

import (
	"testing"

	"github.com/chaugan/swinv/internal/arp"
)

// A product whose only clue is its UninstallString had its directory recovered
// and handed to the coverage set -- so the full scan treated its files as
// accounted for and never opened them -- while its component carried no
// location for anything to join against. Mosquitto came out of a full scan of
// a real machine with a registry entry, no PE component, and a listening
// socket on 1883 that nothing could name.
func TestComponentFromRegistryCarriesRecoveredLocations(t *testing.T) {
	c := componentFromRegistry(arp.Entry{
		DisplayName:     "Eclipse Mosquitto MQTT broker (64 bit)",
		DisplayVersion:  "2.0.18",
		UninstallString: `C:\Program Files\mosquitto\Uninstall.exe`,
	})
	if len(c.Locations) != 1 || c.Locations[0] != `C:\Program Files\mosquitto` {
		t.Errorf("locations = %v, want the directory recovered from UninstallString", c.Locations)
	}
}

// InstallLocation stays first and most authoritative, and a second value
// pointing at the same directory does not duplicate it.
func TestComponentFromRegistryPrefersInstallLocation(t *testing.T) {
	c := componentFromRegistry(arp.Entry{
		DisplayName:     "App",
		InstallLocation: `C:\Program Files\App`,
		DisplayIcon:     `C:\Program Files\App\app.exe,0`,
		UninstallString: `C:\Program Files\App\Support\unins.exe`,
	})
	if len(c.Locations) != 2 || c.Locations[0] != `C:\Program Files\App` {
		t.Errorf("locations = %v", c.Locations)
	}
	if c.Locations[1] != `C:\Program Files\App\Support` {
		t.Errorf("second location = %q", c.Locations[1])
	}
}

// An MSI product whose UninstallString is just msiexec points at no directory
// at all, and inventing one would attribute half of System32 to it.
func TestComponentFromRegistryWithNothingToRecover(t *testing.T) {
	c := componentFromRegistry(arp.Entry{
		DisplayName:     "Some MSI",
		UninstallString: `MsiExec.exe /X{1234-5678}`,
	})
	if len(c.Locations) != 0 {
		t.Errorf("locations = %v, want none", c.Locations)
	}
}
