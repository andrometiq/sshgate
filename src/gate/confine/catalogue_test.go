package confine

import (
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/classify"
)

func TestCatalogueControls(t *testing.T) {
	t.Run("U-ZgrepControlFires", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "input.gz")
		file, err := os.Create(input)
		if err != nil {
			t.Fatal(err)
		}
		writer := gzip.NewWriter(file)
		if _, err = writer.Write([]byte("PATTERN\n")); err != nil {
			t.Fatal(err)
		}
		if err = writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		helper, err := filepath.Abs("../../../tests/testdata/greppy.sh")
		if err != nil {
			t.Fatal(err)
		}
		sink := filepath.Join(dir, "sink")
		command := exec.Command("zgrep", "PATTERN", input)
		command.Env = append(os.Environ(), "GREP="+helper, "SINK="+sink)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("zgrep control: %v: %s", err, output)
		}
		if _, err := os.Stat(sink); err != nil {
			t.Fatalf("control did not create sink: %v", err)
		}
	})
}

func TestCatalogueRouting(t *testing.T) {
	t.Run("U-CatalogueRouting", func(t *testing.T) {
		for _, command := range []string{
			"git config user.name attacker", "git branch newbranch", "git remote add evil https://example.invalid/repo",
			"git diff --output=/tmp/pwned", "git show --output=/tmp/pwned", "git log --output=/tmp/pwned",
			"file -C", "sysctl --system", "command sh -c 'touch /tmp/pwned' -v",
		} {
			t.Run(command, func(t *testing.T) {
				if got := classify.Classify(command); got != classify.KindWrite {
					t.Errorf("routing = %v, want write", got)
				}
			})
		}
	})
}
