package confine

import (
	"path/filepath"
	"strings"
	"syscall"
)

// Lane2NoDockerConfig is a directory that cannot exist: procfs refuses to
// create entries, even for root. The docker CLI treats a missing config dir as
// "defaults": the local daemon socket, no hooks, system plugin dirs only.
const Lane2NoDockerConfig = "/proc/sshgate-no-docker-config"

// Lane2Env returns a daemon read's entire environment. It is built from
// nothing, so no inherited DOCKER_*, SYSTEMD_*, PAGER, LC_* or SSH-injected
// variable reaches a client that talks to a root-equivalent daemon.
//
// DOCKER_CONFIG is pinned to Lane2NoDockerConfig so the docker CLI never reads
// the gate user's ~/.docker: a config.json there could switch the endpoint
// (currentContext), add CLI hooks, or put plugin binaries in cli-plugins/.
// TMPDIR names the jail's only writable directory.
func Lane2Env() []string {
	return []string{
		"PATH=/usr/bin:/bin", "LANG=C", "SYSTEMD_COLORS=0", "TERM=dumb", "TMPDIR=/dev/shm",
		"DOCKER_CONFIG=" + Lane2NoDockerConfig,
	}
}

// EncodeArgv is a daemon read's fd-3 command: its argv joined by NUL. Grammar
// tokens never contain NUL.
func EncodeArgv(argv []string) string { return strings.Join(argv, "\x00") }

// DecodeArgv parses an EncodeArgv command for client: 2 to 64 non-empty
// tokens of at most 4096 bytes, argv[0] an absolute clean path named client.
func DecodeArgv(command, client string) ([]string, error) {
	argv := strings.Split(command, "\x00")
	if len(argv) < 2 || len(argv) > 64 || !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != argv[0] || filepath.Base(argv[0]) != client {
		return nil, syscall.EINVAL
	}
	for _, token := range argv {
		if token == "" || len(token) > 4096 {
			return nil, syscall.EINVAL
		}
	}
	return argv, nil
}
