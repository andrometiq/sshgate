/* The daemon-read fixture's plugin: proof that the client ran another program. */
#include <stdio.h>

int main(int argc, char **argv) {
	printf("PLUGIN-RAN %s\n", argc > 1 ? argv[1] : "");
	return 0;
}
