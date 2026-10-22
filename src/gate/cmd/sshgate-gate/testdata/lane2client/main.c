/*
 * The daemon-read test client. It is installed by copy under the names
 * systemctl and docker in a fixed directory, and its behaviour comes from a
 * grammar-valid argument sg-<mode>.<nonce> (a positional, or a docker filter
 * value name=sg-...), so an agent-shaped line reaches it through the real
 * parser. Its own directory is dirname(argv[0]), the fixed directory, never
 * /proc/self/exe. Each mode prints one fixed line; a failure names its errno.
 *
 * report: how it was exec'd (path, argv, env, cwd, whether stdin is
 *         /dev/null) as one JSON line, in the gate tests' execReport shape.
 * host: connect to the socket of the gate-chosen --host=unix://<path>, send the
 *       nonce, print HOST-CONNECTED <nonce> or host:<errno>.
 * exec: execve <own dir>/plugins/sg-plugin <nonce>, or print exec:<errno>.
 * reexec: execve /proc/self/exe as sg-report.<nonce>.
 * loader: execve the system loader on /usr/bin/id, or print loader:<errno>.
 * memfd: run a memfd copy of sg-plugin; print memfd:<errno> if the memfd
 *        cannot be created, memfd-exec:<errno> if it cannot be executed.
 * memfd-flags: print memfd-flags:<the flags memfd mode first requests>.
 * memfd-secret: print memfd-secret:<errno or created>.
 * dgram: print dgram:<errno or created> for socket(AF_UNIX, SOCK_DGRAM).
 * unix-<n>: connect to each of the first n paths in <own dir>/sockets, sending
 *           the nonce, and print unix-<i>:<connected or errno> for each.
 * unix-wait-<n>: connect to path n and send the nonce; wait (at most 10 s)
 *           for <own dir>/go; connect to path n again and send the nonce;
 *           print unix-again:<connected or errno>, or handshake:timeout.
 * abstract: connect to the abstract name in <own dir>/abstract.
 * tcp: connect to the IPv4 address:port in <own dir>/tcp.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/un.h>
#include <unistd.h>

/* The memfd mode requests MFD_EXEC whatever the build headers say, exactly as
 * the confine memfd probe does, and falls back without it only on the
 * kernel's EINVAL (before 6.3, where every memfd is executable).
 * SG_UNDEF_MFD_EXEC builds as with headers that predate it. */
#ifdef SG_UNDEF_MFD_EXEC
#undef MFD_EXEC
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#define SG_MEMFD_FLAGS (MFD_CLOEXEC | MFD_EXEC)

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

static const char *errname(int e) {
	switch (e) {
	case EACCES: return "EACCES";
	case EPERM: return "EPERM";
	case ENOENT: return "ENOENT";
	case ECONNREFUSED: return "ECONNREFUSED";
	case ENOSYS: return "ENOSYS";
	case EINVAL: return "EINVAL";
	default: {
		static char buffer[32];
		snprintf(buffer, sizeof buffer, "errno=%d", e);
		return buffer;
	}
	}
}

static char own_dir[4096];

/* own_file reads <own dir>/<name> into buffer, line by line. */
static int own_file(const char *name, char lines[][256], int max) {
	char path[4352];
	snprintf(path, sizeof path, "%s/%s", own_dir, name);
	FILE *file = fopen(path, "r");
	if (file == NULL)
		return 0;
	int n = 0;
	while (n < max && fgets(lines[n], 256, file) != NULL) {
		lines[n][strcspn(lines[n], "\n")] = '\0';
		n++;
	}
	fclose(file);
	return n;
}

/* connect_send connects to a path (or, with abstract, an abstract name) and
 * sends the nonce; it returns 0 or an errno. */
static int connect_send(const char *name, int abstract, const char *nonce) {
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	size_t length = strlen(name);
	if (length + abstract >= sizeof address.sun_path)
		return EINVAL;
	memcpy(address.sun_path + abstract, name, length);
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return errno;
	socklen_t size = abstract ? (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + length) : sizeof address;
	if (connect(fd, (struct sockaddr *)&address, size) != 0 || dprintf(fd, "%s\n", nonce) < 0) {
		int e = errno;
		close(fd);
		return e;
	}
	close(fd);
	return 0;
}

static int plugin(char **argv, const char *nonce, int memfd) {
	char path[4352];
	snprintf(path, sizeof path, "%s/plugins/sg-plugin", own_dir);
	char *args[] = {"sg-plugin", (char *)nonce, NULL};
	if (!memfd) {
		execve(path, args, environ);
		printf("exec:%s\n", errname(errno));
		return 1;
	}
	FILE *source = fopen(path, "r");
	int fd = memfd_create("sg", SG_MEMFD_FLAGS);
	if (fd < 0 && errno == EINVAL)
		fd = memfd_create("sg", MFD_CLOEXEC);
	if (fd < 0) {
		printf("memfd:%s\n", errname(errno));
		return 1;
	}
	char buffer[65536];
	size_t n;
	while (source != NULL && (n = fread(buffer, 1, sizeof buffer, source)) > 0)
		if (write(fd, buffer, n) != (ssize_t)n)
			break;
	fexecve(fd, args, environ);
	printf("memfd-exec:%s\n", errname(errno));
	return 1;
}

static int unix_mode(const char *mode, const char *nonce) {
	char lines[8][256];
	int count = own_file("sockets", lines, 8);
	if (strncmp(mode, "unix-wait-", 10) == 0) {
		int n = atoi(mode + 10);
		if (n < 1 || n > count) {
			printf("unix:no-socket\n");
			return 1;
		}
		int e = connect_send(lines[n - 1], 0, nonce);
		if (e != 0) {
			printf("unix-first:%s\n", errname(e));
			return 1;
		}
		char go[4352];
		snprintf(go, sizeof go, "%s/go", own_dir);
		for (int i = 0; access(go, F_OK) != 0; i++) {
			if (i == 1000) {
				printf("handshake:timeout\n");
				return 1;
			}
			struct timespec tick = {0, 10000000};
			nanosleep(&tick, NULL);
		}
		e = connect_send(lines[n - 1], 0, nonce);
		printf("unix-again:%s\n", e == 0 ? "connected" : errname(e));
		return 0;
	}
	int n = atoi(mode + 5);
	if (n < 1 || n > count) {
		printf("unix:no-socket\n");
		return 1;
	}
	for (int i = 0; i < n; i++) {
		int e = connect_send(lines[i], 0, nonce);
		printf("unix-%d:%s\n", i + 1, e == 0 ? "connected" : errname(e));
	}
	return 0;
}

static int tcp(const char *nonce) {
	char lines[1][256];
	if (own_file("tcp", lines, 1) != 1) {
		printf("tcp:no-address\n");
		return 1;
	}
	char *colon = strrchr(lines[0], ':');
	struct sockaddr_in address = {.sin_family = AF_INET};
	if (colon == NULL)
		return 1;
	*colon = '\0';
	address.sin_port = htons((unsigned short)atoi(colon + 1));
	inet_pton(AF_INET, lines[0], &address.sin_addr);
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof address) != 0 || dprintf(fd, "%s\n", nonce) < 0) {
		printf("tcp:%s\n", errname(errno));
		return 1;
	}
	printf("tcp:connected\n");
	return 0;
}

/* mode_of finds sg-<mode>.<nonce> as an argument or a filter value. */
static int mode_of(int argc, char **argv, char *mode, size_t size, const char **nonce) {
	for (int i = 1; i < argc; i++) {
		char *p = strstr(argv[i], "sg-");
		if (p == NULL || (p != argv[i] && p[-1] != '='))
			continue;
		char *dot = strrchr(p, '.');
		if (dot == NULL || (size_t)(dot - p - 3) >= size)
			continue;
		memcpy(mode, p + 3, (size_t)(dot - p - 3));
		mode[dot - p - 3] = '\0';
		*nonce = dot + 1;
		return i;
	}
	return 0;
}

static int ps_connect(int argc, char **argv) {
	char lines[1][256], message[272];
	int verb = 1;
	while (verb < argc && argv[verb][0] == '-')
		verb++;
	if (verb == argc || strcmp(argv[verb], "ps") != 0 || own_file("ps-connect", lines, 1) != 1)
		return -1;
	const char *path = NULL;
	for (int i = 1; i < argc; i++)
		if (strncmp(argv[i], "--host=unix://", 14) == 0)
			path = argv[i] + 14;
	if (path == NULL) {
		printf("ps-connect:no-endpoint\n");
		return 1;
	}
	snprintf(message, sizeof message, "SG-PS %s", lines[0]);
	int e = connect_send(path, 0, message);
	if (e != 0) {
		printf("ps-connect:%s\n", errname(e));
		return 1;
	}
	printf("CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES\n");
	return 0;
}

int main(int argc, char **argv) {
	char self[4096];
	snprintf(self, sizeof self, "%s", argv[0]);
	snprintf(own_dir, sizeof own_dir, "%s", dirname(self));
	int ps = ps_connect(argc, argv);
	if (ps >= 0)
		return ps;

	char mode[64];
	const char *nonce = NULL;
	int at = mode_of(argc, argv, mode, sizeof mode, &nonce);
	if (at == 0) {
		printf("SG-FIXTURE no mode\n");
		return 2;
	}
#ifdef SG_REPLACEMENT
	printf("REPLACED-RAN %s\n", nonce);
	return 0;
#endif
	if (strcmp(mode, "report") == 0)
		return report(argc, argv);
	if (strcmp(mode, "host") == 0)
		return host(argc, argv, nonce);
	if (strcmp(mode, "exec") == 0 || strcmp(mode, "memfd") == 0)
		return plugin(argv, nonce, strcmp(mode, "memfd") == 0);
	if (strcmp(mode, "reexec") == 0) {
		char token[128];
		snprintf(token, sizeof token, "sg-report.%s", nonce);
		argv[at] = token;
		execve("/proc/self/exe", argv, environ);
		printf("reexec:%s\n", errname(errno));
		return 1;
	}
	if (strcmp(mode, "loader") == 0) {
		char *args[] = {"/lib64/ld-linux-x86-64.so.2", "/usr/bin/id", NULL};
		execve(args[0], args, environ);
		printf("loader:%s\n", errname(errno));
		return 1;
	}
	if (strcmp(mode, "memfd-flags") == 0) {
		printf("memfd-flags:%#x\n", (unsigned)SG_MEMFD_FLAGS);
		return 0;
	}
	if (strcmp(mode, "memfd-secret") == 0) {
		long fd = syscall(447, 0);
		printf("memfd-secret:%s\n", fd >= 0 ? "created" : errname(errno));
		return 0;
	}
	if (strcmp(mode, "dgram") == 0) {
		int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
		printf("dgram:%s\n", fd >= 0 ? "created" : errname(errno));
		return 0;
	}
	if (strncmp(mode, "unix-", 5) == 0)
		return unix_mode(mode, nonce);
	if (strcmp(mode, "abstract") == 0) {
		char lines[1][256];
		if (own_file("abstract", lines, 1) != 1)
			return 1;
		int e = connect_send(lines[0], 1, nonce);
		printf("abstract:%s\n", e == 0 ? "connected" : errname(e));
		return 0;
	}
	if (strcmp(mode, "tcp") == 0)
		return tcp(nonce);
	printf("SG-FIXTURE unknown mode %s\n", mode);
	return 2;
}
