package confine

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
