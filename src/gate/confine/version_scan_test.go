package confine

import (
	"debug/buildinfo"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDistGateHasNoMutationBuild(t *testing.T) {
	files, err := os.ReadDir("../../../dist/gate")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, file := range files {
		if file.IsDir() || strings.HasSuffix(file.Name(), ".sha256") {
			continue
		}
		info, err := buildinfo.ReadFile(filepath.Join("../../../dist/gate", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		count++
		for _, setting := range info.Settings {
			if setting.Key == "-tags" && strings.Contains(setting.Value, "jail_mutation") || setting.Key == "-ldflags" && strings.Contains(setting.Value, "jailmut") {
				t.Errorf("%s has mutation setting %s=%s", file.Name(), setting.Key, setting.Value)
			}
		}
	}
	if count == 0 {
		t.Fatal("no committed gate binary checked")
	}
}
