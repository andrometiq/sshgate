/*
 * The daemon-read test client. It is installed by copy under the names
 * systemctl and docker in a fixed directory, and its behaviour comes from a
 * grammar-valid positional, sg-<mode>.<nonce>, so an agent-shaped line reaches
 * it through the real parser.
 *
 * report: print how it was exec'd (path, argv, env, cwd, whether stdin is
 * /dev/null) as one JSON line, in the gate tests' execReport shape.
 *
 * host: connect to the socket in the gate-chosen --host=unix://<path>, send
 * the nonce and a newline, and print HOST-CONNECTED <nonce> or host:errno=<n>.
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

extern char **environ;

static void json_string(const char *s) {
	putchar('"');
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\')
			printf("\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			printf("\\u%04x", c);
		else
			putchar(c);
	}
	putchar('"');
}

static void json_strings(char **list, int count) {
	putchar('[');
	for (int i = 0; count < 0 ? list[i] != NULL : i < count; i++) {
		if (i > 0)
			putchar(',');
		json_string(list[i]);
	}
	putchar(']');
}

static int report(int argc, char **argv) {
	char exe[PATH_MAX], cwd[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
	exe[n < 0 ? 0 : n] = '\0';
	if (getcwd(cwd, sizeof cwd) == NULL)
		cwd[0] = '\0';
	struct stat in, nul;
	int stdin_null = fstat(0, &in) == 0 && stat("/dev/null", &nul) == 0 && S_ISCHR(in.st_mode) && in.st_rdev == nul.st_rdev;
	printf("{\"path\":");
	json_string(exe);
	printf(",\"args\":");
	json_strings(argv, argc);
	printf(",\"env\":");
	json_strings(environ, -1);
	printf(",\"cwd\":");
	json_string(cwd);
	printf(",\"stdin_is_devnull\":%s}\n", stdin_null ? "true" : "false");
	return 0;
}

static int host(int argc, char **argv, const char *nonce) {
	const char *path = NULL;
	for (int i = 1; i < argc; i++) {
		if (strncmp(argv[i], "--host=unix://", 14) == 0)
			path = argv[i] + 14;
	}
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	if (path == NULL || strlen(path) >= sizeof address.sun_path) {
		printf("host:no-endpoint\n");
		return 1;
	}
	strcpy(address.sun_path, path);
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof address) != 0 ||
	    dprintf(fd, "%s\n", nonce) < 0) {
		printf("host:errno=%d\n", errno);
		return 1;
	}
	printf("HOST-CONNECTED %s\n", nonce);
	return 0;
}

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		if (strncmp(argv[i], "sg-report.", 10) == 0)
			return report(argc, argv);
		if (strncmp(argv[i], "sg-host.", 8) == 0)
			return host(argc, argv, argv[i] + 8);
	}
	printf("SG-FIXTURE no mode\n");
	return 2;
}
