package mobile

import (
	"testing"
)

func TestGetVersion(t *testing.T) {
	version := GetVersion()
	if version == "" {
		t.Error("GetVersion returned empty string")
	}
}

func TestGetBuildDate(t *testing.T) {
	date := GetBuildDate()
	if date == "" {
		t.Error("GetBuildDate returned empty string")
	}
}

func TestGetLibraryInfo(t *testing.T) {
	info := GetLibraryInfo()
	if info == nil {
		t.Fatal("GetLibraryInfo returned nil")
	}

	if info.Version == "" {
		t.Error("LibraryInfo Version is empty")
	}

	if len(info.Features) == 0 {
		t.Error("LibraryInfo Features is empty")
	}
}

func TestLibraryInfoFields(t *testing.T) {
	info := GetLibraryInfo()

	// Test field access directly (gomobile auto-generates getters)
	if info.Version == "" {
		t.Error("Version is empty")
	}

	if info.BuildDate == "" {
		t.Error("BuildDate is empty")
	}

	if len(info.Features) == 0 {
		t.Error("Features is empty")
	}
}

func TestQuickVerifyWithInvalidConfig(t *testing.T) {
	// Quick verify should fail quickly with invalid config
	err := QuickVerify("", 0, "", "", "")
	if err == nil {
		t.Error("Expected error for empty config")
	}
}

func TestToConfigCopiesJumpChain(t *testing.T) {
	cfg := &SshConfig{Host: "target", Port: 22, Username: "t", Jump: &SshConfig{Host: "jump", Port: 2222, Username: "j"}}
	got := toConfig(cfg)
	if got.Host != "target" || got.Jump == nil || got.Jump.Host != "jump" || got.Jump.Port != 2222 {
		t.Fatalf("jump chain not copied: %+v", got)
	}
	if toConfig(nil) != nil {
		t.Error("nil should stay nil")
	}
}

func TestToConfigStopsOnCycle(t *testing.T) {
	a := &SshConfig{Host: "a", Port: 22, Username: "u", PrivateKey: "k"}
	a.Jump = a
	if err := a.Validate(); err == nil {
		t.Error("cyclic jump chain should fail validation")
	}
}
