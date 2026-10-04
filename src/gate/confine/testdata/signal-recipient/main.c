#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int signal_number = atoi(argv[1]);
    sigset_t blocked, pending;
    if ((signal_number != SIGIO && signal_number != SIGUSR1) ||
        sigemptyset(&blocked) || sigaddset(&blocked, signal_number) ||
        sigprocmask(SIG_BLOCK, &blocked, NULL)) return 3;
    if (puts("READY") < 0 || fflush(stdout)) return 4;
    char request[2];
    size_t received = 0;
    while (received < sizeof(request)) {
        ssize_t count = read(STDIN_FILENO, request + received, sizeof(request) - received);
        if (count <= 0) return 5;
        received += (size_t)count;
    }
    if (request[0] != 's' || request[1] != '\n' || sigpending(&pending)) return 6;
    int present = sigismember(&pending, signal_number);
    if (present < 0 || printf("%s=%s\nVERDICT ok\n", signal_number == SIGIO ? "sigio" : "signal", present ? "pending" : "absent") < 0 || fflush(stdout)) return 7;
    return 0;
}
