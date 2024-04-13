#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void signalHandler(int signalNumber) {
    if (signalNumber == SIGINT) {
        printf("UID at SIGINT: %d\n", getuid());
        printf("Received SIGINT\n");
    } else if (signalNumber == SIGTERM) {
        printf("UID at SIGTERM: %d\n", getuid());
        printf("Received SIGTERM\n");
    } else {
        printf("Received signal: %d\n", signalNumber);
    }
}

int main() {
    // Register signal handlers
    if (signal(SIGINT, signalHandler) == SIG_ERR) {
        printf("Can't catch SIGINT\n");
    }

    if (signal(SIGTERM, signalHandler) == SIG_ERR) {
        printf("Can't catch SIGTERM\n");
    }

    printf("Raising SIGTERM signal.\n");
    raise(SIGTERM);

    printf("Raising SIGINT signal.\n");
    raise(SIGINT);

    printf("UID at the end: %d\n", getuid());
    return 0;
}
