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
